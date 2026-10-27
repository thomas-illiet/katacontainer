#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64) multiarch=x86_64-linux-gnu ;;
  aarch64|arm64) multiarch=aarch64-linux-gnu ;;
  *) echo "unsupported build architecture: $(uname -m)" >&2; exit 1 ;;
esac

exec go run github.com/cilium/ebpf/cmd/bpf2go \
  -cc clang \
  -cflags "-O2 -g -Wall -Werror" \
  kata ../../bpf/guard.bpf.c -- \
  -I/usr/include -I/usr/include/$multiarch
