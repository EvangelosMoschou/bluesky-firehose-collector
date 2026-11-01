/*
 * fuzz_jetstream.c — libFuzzer / OSS-Fuzz entry point.
 *
 * Target: src/jetstream_classify.c, the only code in the collector that
 * interprets attacker-controlled bytes. Every byte a Jetstream peer sends
 * reaches it, so the fuzzer is fed the raw frame exactly as received —
 * no NUL terminator, no length assumptions.
 *
 * Build (Clang):
 *   make fuzz-clang
 * Run:
 *   ./fuzz_jetstream corpus/
 */

#include <stddef.h>
#include <stdint.h>

#include "../src/jetstream_classify.h"

/* The collector never buffers more than MAX_FRAME_SIZE bytes per frame. */
#define MAX_FRAME_SIZE 16384

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > MAX_FRAME_SIZE) return 0;

    int kind = jetstream_classify((const char *)data, size);

    if (kind < JETSTREAM_COMMIT || kind > JETSTREAM_INFO) {
        __builtin_trap(); /* out-of-range counter would index past the tally */
    }
    if (jetstream_classify((const char *)data, size) != kind) {
        __builtin_trap(); /* classification must be deterministic */
    }
    return 0;
}
