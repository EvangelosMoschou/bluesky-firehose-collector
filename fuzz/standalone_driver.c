/*
 * standalone_driver.c — dependency-free fuzzer for boxes without Clang.
 *
 * There is no libFuzzer here, so this does unguided mutation over a seed
 * corpus with a small set of JSON-aware mutations (bracket, quote and escape
 * insertion, truncation, token splicing). That is enough to reach the shallow
 * parser bugs, and ASan/UBSan turn them into hard crashes.
 *
 * The input that triggered a crash is written to crash-current.bin by an ASan
 * death callback, so a reproducer always survives the abort.
 *
 * Build:  make fuzz-gcc
 * Run:    ./fuzz_jetstream_standalone corpus/ [iterations]
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/jetstream_classify.h"

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
#include <sanitizer/common_interface_defs.h>
#define HAVE_ASAN 1
#endif

#define MAX_FRAME 16384
#define MAX_SEEDS 256
#define MAX_SEED_LEN MAX_FRAME

static const uint8_t *g_current_data;
static size_t g_current_size;
static const char *g_crash_path = "crash-current.bin";

static void dump_current_input(void) {
    FILE *f = fopen(g_crash_path, "wb");
    if (!f) return;
    fwrite(g_current_data, 1, g_current_size, f);
    fclose(f);
    fprintf(stderr, "\n[crash] input written to %s (%zu bytes)\n",
            g_crash_path, g_current_size);
}

#ifdef HAVE_ASAN
__attribute__((constructor)) static void install_crash_hook(void) {
    __sanitizer_set_death_callback(dump_current_input);
}
#endif

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

static uint32_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 32);
}

static const char JSON_TRICKS[] = "{}[]\":,\\0123456789-.eEtrufalsn \t\n\x00\xff";

struct seed {
    uint8_t *data;
    size_t len;
};

static struct seed seeds[MAX_SEEDS];
static size_t seed_count;

static int load_seed(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint8_t *buf = malloc(MAX_SEED_LEN);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, MAX_SEED_LEN, f);
    fclose(f);
    if (seed_count >= MAX_SEEDS) { free(buf); return -1; }
    seeds[seed_count].data = buf;
    seeds[seed_count].len = n;
    seed_count++;
    return 0;
}

static void mutate(uint8_t *buf, size_t *len) {
    int edits = 1 + (int)(rnd() % 6);
    for (int e = 0; e < edits; e++) {
        size_t n = *len;
        switch (rnd() % 9) {
        case 0: /* flip a random bit */
            if (n) buf[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8));
            break;
        case 1: /* overwrite with a JSON-significant byte */
            if (n) buf[rnd() % n] = (uint8_t)JSON_TRICKS[rnd() % (sizeof(JSON_TRICKS) - 1)];
            break;
        case 2: /* insert a byte */
            if (n + 1 < MAX_FRAME) {
                size_t at = n ? rnd() % n : 0;
                memmove(buf + at + 1, buf + at, n - at);
                buf[at] = (uint8_t)JSON_TRICKS[rnd() % (sizeof(JSON_TRICKS) - 1)];
                *len = n + 1;
            }
            break;
        case 3: /* delete a byte */
            if (n > 1) {
                size_t at = rnd() % n;
                memmove(buf + at, buf + at + 1, n - at - 1);
                *len = n - 1;
            }
            break;
        case 4: /* truncate mid-structure */
            if (n > 1) *len = 1 + rnd() % n;
            break;
        case 5: /* duplicate a slice */
            if (n > 2) {
                size_t a = rnd() % n;
                size_t b = a + rnd() % (n - a);
                size_t cl = b - a;
                if (n + cl < MAX_FRAME) {
                    memmove(buf + a + cl, buf + a, n - a);
                    memcpy(buf + a, buf + a + cl, cl);
                    *len = n + cl;
                }
            }
            break;
        case 6: /* splice in bytes from another seed */
            if (seed_count) {
                struct seed *s = &seeds[rnd() % seed_count];
                if (s->len && n < MAX_FRAME) {
                    size_t take = 1 + rnd() % s->len;
                    if (take > MAX_FRAME - n) take = MAX_FRAME - n;
                    size_t at = s->len > take ? rnd() % (s->len - take) : 0;
                    size_t dst = n ? rnd() % n : 0;
                    memmove(buf + dst + take, buf + dst, n - dst);
                    memcpy(buf + dst, s->data + at, take);
                    *len = n + take;
                }
            }
            break;
        case 7: /* grow a run of quotes — stresses string termination */
            if (n + 8 < MAX_FRAME) {
                size_t at = n ? rnd() % n : 0;
                memmove(buf + at + 8, buf + at, n - at);
                memset(buf + at, '"', 8);
                *len = n + 8;
            }
            break;
        default: /* repeated backslashes — stresses escape handling */
            if (n + 8 < MAX_FRAME) {
                size_t at = n ? rnd() % n : 0;
                memmove(buf + at + 8, buf + at, n - at);
                memset(buf + at, '\\', 8);
                *len = n + 8;
            }
            break;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <seed-file|seed-dir>... [iterations]\n", argv[0]);
        return 2;
    }

    long iterations = 200000;
    int seed_args = argc - 1;
    char *last = argv[argc - 1];
    char *endp = NULL;
    long maybe = strtol(last, &endp, 10);
    if (endp && *endp == '\0' && maybe > 0) {
        iterations = maybe;
        seed_args = argc - 2;
    }
    if (seed_args < 1) {
        fprintf(stderr, "no seeds given\n");
        return 2;
    }

    for (int i = 1; i <= seed_args; i++) {
        if (load_seed(argv[i]) != 0) {
            fprintf(stderr, "warning: could not read seed %s\n", argv[i]);
        }
    }
    if (!seed_count) {
        fprintf(stderr, "no usable seeds\n");
        return 2;
    }

    fprintf(stderr, "seeds=%zu iterations=%ld\n", seed_count, iterations);

    uint8_t *buf = malloc(MAX_FRAME);
    if (!buf) return 1;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (long it = 0; it < iterations; it++) {
        struct seed *s = &seeds[rnd() % seed_count];
        size_t len = s->len;
        memcpy(buf, s->data, len);
        mutate(buf, &len);

        g_current_data = buf;
        g_current_size = len;

        int kind = jetstream_classify((const char *)buf, len);
        if (kind < JETSTREAM_COMMIT || kind > JETSTREAM_INFO) {
            fprintf(stderr, "invariant violated: kind=%d\n", kind);
            dump_current_input();
            return 1;
        }

        if ((it & 0x3FFFF) == 0 && it) {
            fprintf(stderr, "\r%ld/%ld", it, iterations);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (double)(t1.tv_sec - t0.tv_sec) +
                  (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    fprintf(stderr, "\n%ld iterations in %.2fs (%.0f/s) — no findings\n",
            iterations, secs, secs > 0 ? (double)iterations / secs : 0.0);
    free(buf);
    return 0;
}
