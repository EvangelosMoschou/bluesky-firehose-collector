# Fuzzing the Jetstream frame classifier

`src/jetstream_classify.c` is the only code in this collector that interprets
attacker-controlled bytes. Every frame a Jetstream peer sends — up to
`MAX_FRAME_SIZE` (16 KiB), from an endpoint this program does not control —
reaches it. Everything else in the collector is sockets, queues and counters.

The classifier takes `(const char *frame, size_t len)` and never assumes the
buffer is NUL-terminated, so a fuzzer can feed it raw bytes with no shim.

## Targets

| Command | Toolchain | Use |
|---|---|---|
| `make fuzz-clang` | Clang + libFuzzer + ASan + UBSan | coverage-guided runs, OSS-Fuzz |
| `make fuzz-gcc` | any gcc + ASan + UBSan | unguided mutation, works everywhere |
| `make test` | gcc + ASan + UBSan | behaviour regression for the extraction |
| `make corpus` | — | regenerate the seed corpus |
| `make run` | — | run the standalone driver over the corpus |

```sh
cd fuzz
make corpus
make test
make run                 # 200k iterations
make run ITERS=10000000  # longer campaign
```

The standalone driver writes the input that triggered a crash to
`crash-current.bin` via an ASan death callback, so a reproducer always survives
the abort.

## Seed corpus

The 24-hour dataset in `data/` is aggregate metrics, not raw frames, so real
frames are not committed. `make_corpus.sh` synthesises 31 seeds covering every
branch the classifier takes:

- one well-formed frame per counter (`commit`, `identity`, `account`)
- `kind` absent, non-string, null, nested, duplicated, or positioned last
- truncation mid-string, mid-key, mid-escape
- lone backslash, invalid UTF-8, high bytes, control characters
- deep nesting and 300-key input to force jsmn into its token-exhaustion path

## Results

Run on 2026-11-01, gcc 13.3.0, `-fsanitize=address,undefined`.

| Target | Iterations | Findings |
|---|---|---|
| `src/jetstream_classify.c` (current) | 300,000 | none |
| original inline logic (pre-extraction) | 1,000,000 | none |

**The negative result is the honest headline.** The bounds check in
`json_string_eq()` is hardening, not a fix for a reachable bug: the original
code rejects a half-built token on the length comparison before reaching
`strncmp()`, and a faithful reproduction of it survived a million mutations.
Nothing here should be written up as a vulnerability.

### Harness validation

A "found nothing" result means nothing unless the harness can find something.
Weakening the scan bound from `i + 1 < r` to `i <= r` (so the loop reads
`tokens[r]`) makes the token-exhaustion seed trigger:

```
ERROR: AddressSanitizer: stack-buffer-overflow
READ of size 4 ... in jetstream_classify
[crash] input written to crash-current.bin
```

So the driver reaches the target, ASan catches memory errors, and the
reproducer is preserved. The weakened copy is deliberately not committed.

## Next steps

1. Run `make fuzz-clang` with a real libFuzzer campaign — the standalone driver
   has no coverage feedback, so it only exercises shallow, length-local bugs.
2. Feed known-crashing history back into `corpus/` as regression seeds.
3. If this is integrated into OSS-Fuzz, add `fuzz/build.sh` and a
   `project.yaml`, and point `$SRC` at `src/`.
4. The socket path (`rx_frame` reassembly across `LWS_CALLBACK_CLIENT_RECEIVE`
   fragments) is not covered yet. It is the next thing a hostile peer controls:
   the truncation counter and the 16 KiB cap are the invariants worth testing.
