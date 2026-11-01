/*
 * jetstream_classify.h
 *
 * Classifies one Jetstream firehose frame by its top-level "kind" field.
 *
 * Extracted from the consumer thread so the exact code path that handles
 * untrusted network input can be fuzzed in isolation, without threads,
 * sockets or libwebsockets.
 */

#ifndef JETSTREAM_CLASSIFY_H
#define JETSTREAM_CLASSIFY_H

#include <stddef.h>

#define JETSTREAM_MAX_TOKENS 256

enum jetstream_kind {
    JETSTREAM_COMMIT = 0,
    JETSTREAM_IDENTITY,
    JETSTREAM_ACCOUNT,
    JETSTREAM_INFO
};

/*
 * Parse `len` bytes at `frame` and report which counter the frame belongs to.
 *
 * `frame` need not be NUL-terminated: all reads stay within [frame, frame+len).
 * Truncated or malformed frames classify as JETSTREAM_INFO, matching the
 * collector's behaviour when it receives more than MAX_FRAME_SIZE bytes.
 */
int jetstream_classify(const char *frame, size_t len);

#endif /* JETSTREAM_CLASSIFY_H */
