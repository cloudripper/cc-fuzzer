#!/bin/sh
# Fixture build script (never run).
clang -g -O1 -fsanitize=fuzzer,address,undefined -o "$OUT/parser_fuzzer" parser_fuzzer.c ../../../../src/parser.c
