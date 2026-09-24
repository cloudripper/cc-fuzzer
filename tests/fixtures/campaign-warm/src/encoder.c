/* Synthetic target for cc-fuzzer fixtures. Never compiled. */
#include <stdlib.h>
#include <string.h>

int encode_chunk(const unsigned char *in, size_t n, unsigned char **out) {
    unsigned char *buf = malloc(n * 2);
    size_t i, j = 0;
    for (i = 0; i < n; i++) {
        if (in[i] == 0x7d || in[i] == 0x7e) { buf[j++] = 0x7d; buf[j++] = in[i] ^ 0x20; }
        else buf[j++] = in[i];
    }
    *out = buf;
    return (int)j;
}
