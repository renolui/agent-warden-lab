CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -Wall

all: warden.bpf.o warden.skel.h

warden.bpf.o: warden.bpf.c warden.h vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

warden.skel.h: warden.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f warden.bpf.o warden.skel.h

.PHONY: all clean

