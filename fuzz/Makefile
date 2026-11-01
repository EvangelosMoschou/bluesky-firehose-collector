# Fuzzing targets for the Jetstream frame classifier.
#
#   make fuzz-clang   libFuzzer + ASan + UBSan (needs Clang; use for OSS-Fuzz)
#   make fuzz-gcc     standalone mutational driver + ASan + UBSan (any gcc)
#   make corpus       regenerate the seed corpus
#   make run          run the standalone driver over the corpus
#
# The target is ../src/jetstream_classify.c — the only place untrusted
# network bytes are interpreted.

CC     ?= gcc
CLANG  ?= clang
SRC    := ../src/jetstream_classify.c
HDR    := ../src/jetstream_classify.h
DEFS   := -DJSMN_PARENT_LINKS
SAN    := -fsanitize=address,undefined -fno-omit-frame-pointer
WARN   := -Wall -Wextra

ITERS  ?= 200000

.PHONY: all fuzz-clang fuzz-gcc corpus run test clean

all: fuzz-gcc

fuzz-clang: fuzz_jetstream.c $(SRC) $(HDR)
	$(CLANG) -g -O1 $(WARN) $(DEFS) $(SAN) \
		-fsanitize=fuzzer \
		fuzz_jetstream.c $(SRC) -o fuzz_jetstream

fuzz-gcc: standalone_driver.c $(SRC) $(HDR)
	$(CC) -g -O1 $(WARN) $(DEFS) $(SAN) \
		standalone_driver.c $(SRC) -o fuzz_jetstream_standalone

corpus:
	./make_corpus.sh

run: fuzz-gcc corpus
	mkdir -p findings
	cd findings && ../fuzz_jetstream_standalone ../corpus/* $(ITERS)

test: classify_test
	./classify_test corpus

classify_test: classify_test.c $(SRC) $(HDR)
	$(CC) -g -O1 $(WARN) $(DEFS) $(SAN) classify_test.c $(SRC) -o classify_test

clean:
	rm -f fuzz_jetstream fuzz_jetstream_standalone classify_test crash-current.bin
	rm -rf findings
