# Makefile for firehose_collector (Raspberry Pi / Raspberry Pi OS)
# Native build on the Pi:
#   sudo apt install build-essential libwebsockets-dev libssl-dev
#   make

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += -DJSMN_PARENT_LINKS $(shell pkg-config --cflags libwebsockets)
LDLIBS  += -pthread -lm $(shell pkg-config --libs libwebsockets)

TARGET := firehose_collector

all: $(TARGET)

$(TARGET): firehose_collector.c jetstream_classify.c jsmn.h jetstream_classify.h
	$(CC) $(CFLAGS) -o $@ firehose_collector.c jetstream_classify.c $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
