# Security policy

## What this program does

`firehose_collector` subscribes to the Bluesky Jetstream WebSocket firehose and
classifies every frame it receives by its top-level `kind` field. The frames are
**untrusted input from a remote peer**: nothing about their content or length is
controlled by this program.

## Trust boundary

| Component | Trust |
|---|---|
| WebSocket frames from Jetstream | **untrusted** |
| `src/jetstream_classify.c` | the only code that interprets untrusted bytes |
| `src/jsmn.h` | vendored JSON tokenizer (MIT, Serge Zaitsev) |
| Controllers, log files | treat as hostile once written |

The WebSocket receive path caps a frame at `MAX_FRAME_SIZE` (16 KiB) and drops
anything beyond it, so a peer cannot make the collector buffer unbounded input.

## Fuzzing

`src/jetstream_classify.c` is designed to be driven directly by a fuzzer, with no
threads, sockets or OpenSSL in the loop.

```sh
cd fuzz
make corpus        # regenerate seed frames
make fuzz-gcc      # standalone driver + ASan + UBSan
make run           # run it
```

With Clang available, `make fuzz-clang` produces a libFuzzer binary suitable for
an OSS-Fuzz integration.

The classifier is length-bounded: it never reads outside `[frame, frame+len)`,
and it does not require the buffer to be NUL-terminated.

## Reporting a vulnerability

Open a private security advisory on this repository, or email the maintainer at
`vagelisaros@gmail.com`. Please do not open a public issue for a memory-safety
bug before it is fixed.

## Scope

In scope: memory-safety bugs reachable through `jetstream_classify()`, resource
exhaustion in the WebSocket receive path, and any crash of the collector caused
by a malformed frame.

Out of scope: denial of service caused by simply not sending frames, issues
requiring a modified binary, and anything that depends on running the collector
as root.
