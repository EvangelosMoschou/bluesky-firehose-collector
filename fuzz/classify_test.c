/*
 * classify_test.c — locks in the classifier's behaviour.
 *
 * The classification loop was extracted from the consumer thread into
 * jetstream_classify(). This test asserts that the extraction did not change
 * how any frame is counted, including the malformed ones.
 *
 *   ./classify_test corpus          assert every expectation
 *   ./classify_test --dump corpus   print what each seed classifies as
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/jetstream_classify.h"

#define MAX_FRAME 16384

struct expectation {
    const char *name;
    int kind;
};

static const struct expectation EXPECT[] = {
    /* well-formed, one per counter */
    {"01_commit", JETSTREAM_COMMIT},
    {"02_identity", JETSTREAM_IDENTITY},
    {"03_account", JETSTREAM_ACCOUNT},
    {"04_unknown_kind", JETSTREAM_INFO},

    /* not a Jetstream-shaped object */
    {"05_empty_object", JETSTREAM_INFO},
    {"06_not_object", JETSTREAM_INFO},
    {"07_bare_string", JETSTREAM_INFO},
    {"08_empty", JETSTREAM_INFO},
    {"09_kind_not_string", JETSTREAM_INFO},
    {"10_kind_null", JETSTREAM_INFO},
    {"12_kind_nested", JETSTREAM_INFO},

    /* first top-level "kind" wins; position in the object does not matter */
    {"11_kind_dup", JETSTREAM_COMMIT},
    {"13_kind_last", JETSTREAM_COMMIT},

    /* truncated input: kind is read before the frame dies */
    {"19_truncated_object", JETSTREAM_COMMIT},
    {"20_bad_utf8", JETSTREAM_COMMIT},
    {"21_high_bytes", JETSTREAM_COMMIT},
    {"23_deep_arrays", JETSTREAM_COMMIT},
    {"24_deep_objects", JETSTREAM_COMMIT},
    {"25_long_string", JETSTREAM_COMMIT},
    {"26_many_keys", JETSTREAM_COMMIT},

    /* malformed before the value could be parsed */
    {"14_unterminated_string", JETSTREAM_INFO},
    {"15_unterminated_key", JETSTREAM_INFO},
    {"16_unterminated_escape", JETSTREAM_INFO},
    {"17_lone_backslash", JETSTREAM_INFO},
    {"27_colon_no_value", JETSTREAM_INFO},

    /* jsmn does not decode escapes, so this is not "commit" */
    {"22_escaped_unicode", JETSTREAM_INFO},
};

static const char *kind_name(int kind) {
    switch (kind) {
    case JETSTREAM_COMMIT:   return "commit";
    case JETSTREAM_IDENTITY: return "identity";
    case JETSTREAM_ACCOUNT:  return "account";
    default:                 return "info";
    }
}

static int read_file(const char *dir, const char *name, unsigned char *buf,
                     size_t *len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    *len = fread(buf, 1, MAX_FRAME, f);
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s [--dump] <corpus-dir>\n", argv[0]);
        return 2;
    }

    int dump = strcmp(argv[1], "--dump") == 0;
    const char *dir = argv[dump ? 2 : 1];

    unsigned char *buf = malloc(MAX_FRAME);
    if (!buf) return 1;

    if (dump) {
        size_t n = sizeof(EXPECT) / sizeof(EXPECT[0]);
        for (size_t i = 0; i < n; i++) {
            size_t len = 0;
            if (read_file(dir, EXPECT[i].name, buf, &len) != 0) {
                printf("%-24s <missing>\n", EXPECT[i].name);
                continue;
            }
            printf("%-24s %s\n", EXPECT[i].name,
                   kind_name(jetstream_classify((const char *)buf, len)));
        }
        free(buf);
        return 0;
    }

    int failures = 0;
    size_t n = sizeof(EXPECT) / sizeof(EXPECT[0]);
    for (size_t i = 0; i < n; i++) {
        size_t len = 0;
        if (read_file(dir, EXPECT[i].name, buf, &len) != 0) {
            printf("MISSING  %s\n", EXPECT[i].name);
            failures++;
            continue;
        }
        int got = jetstream_classify((const char *)buf, len);
        if (got != EXPECT[i].kind) {
            printf("FAIL     %-24s expected=%s got=%s\n", EXPECT[i].name,
                   kind_name(EXPECT[i].kind), kind_name(got));
            failures++;
        }
    }

    if (failures) {
        printf("\n%d/%zu expectations failed\n", failures, n);
        free(buf);
        return 1;
    }
    printf("all %zu expectations passed\n", n);
    free(buf);
    return 0;
}
