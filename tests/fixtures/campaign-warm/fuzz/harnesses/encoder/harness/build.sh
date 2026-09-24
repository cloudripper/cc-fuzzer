#!/bin/sh
# Fixture build script (never run).
clang -g -O1 -fsanitize=fuzzer,address,undefined -o "$OUT/encoder_fuzzer" encoder_fuzzer.c ../../../../src/encoder.c
