CC ?= gcc
CFLAGS ?= -g -O2 -Wall -I../ebpf
LDFLAGS ?= -lbpf -lelf -lz

all: agent-warden

agent-warden: collector.c ../ebpf/warden.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f agent-warden

.PHONY: all clean

