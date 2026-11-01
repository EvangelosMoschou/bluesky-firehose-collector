/*
 * jetstream_classify.c
 *
 * The frame classification path, extracted from the consumer thread.
 *
 * This is the only place in the collector that interprets attacker-controlled
 * bytes: everything else is sockets, queues and counters. Keeping it in one
 * length-bounded function means it can be driven directly by a fuzzer.
 */

#include <string.h>

/* jsmn.h ships its implementation inside the header. Keeping it TU-local here
 * means this file is the single owner of the parser and the header stays safe
 * to include from anywhere else. */
#define JSMN_STATIC
#include "jsmn.h"

#include "jetstream_classify.h"

/*
 * Compare a JSON string token against a C string.
 *
 * jsmn reports a token as [start, end) offsets into the buffer. Those offsets
 * are bounds-checked before use as defence in depth: a token left half-built by
 * a parse that stops mid-string has end == -1, and relying on the length
 * comparison alone to reject it is fragile.
 *
 * Fuzzing has not reached an out-of-range token through this path (see
 * fuzz/README.md), so treat this as hardening rather than a fix for a
 * demonstrated bug.
 */
static int json_string_eq(const char *json, size_t len, const jsmntok_t *tok,
                          const char *s) {
    if (tok->type != JSMN_STRING) return 0;
    if (tok->start < 0 || tok->end < tok->start) return 0;
    if ((size_t)tok->end > len) return 0;

    size_t n = (size_t)(tok->end - tok->start);
    return strlen(s) == n && strncmp(json + tok->start, s, n) == 0;
}

int jetstream_classify(const char *frame, size_t len) {
    jsmntok_t tokens[JETSTREAM_MAX_TOKENS];

    memset(tokens, 0, sizeof(tokens));

    jsmn_parser parser;
    jsmn_init(&parser);

    int r = jsmn_parse(&parser, frame, len, tokens, JETSTREAM_MAX_TOKENS);

    /*
     * r < 0 means the frame was truncated at MAX_FRAME_SIZE or ran out of
     * token slots. Whatever was parsed is still valid and "kind" sits near
     * the front of a Jetstream message, so classify on it rather than
     * discarding the frame. Unparsed slots stay JSMN_UNDEFINED (zeroed
     * above) and end the scan.
     */
    if (r < 0) r = JETSTREAM_MAX_TOKENS;
    if (r <= 0) return JETSTREAM_INFO;
    if (tokens[0].type != JSMN_OBJECT) return JETSTREAM_INFO;

    /* JSMN_PARENT_LINKS: top-level keys are STRING tokens whose parent is the
     * root object, token 0. */
    for (int i = 1; i + 1 < r && tokens[i].type != JSMN_UNDEFINED; i++) {
        if (tokens[i].parent != 0 || tokens[i].type != JSMN_STRING) continue;
        if (!json_string_eq(frame, len, &tokens[i], "kind")) continue;

        const jsmntok_t *val = &tokens[i + 1];
        if (json_string_eq(frame, len, val, "commit")) return JETSTREAM_COMMIT;
        if (json_string_eq(frame, len, val, "identity")) return JETSTREAM_IDENTITY;
        if (json_string_eq(frame, len, val, "account")) return JETSTREAM_ACCOUNT;
        return JETSTREAM_INFO;
    }

    return JETSTREAM_INFO;
}
