/* Synthetic target for cc-fuzzer fixtures. Never compiled. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct chunk { char tag[4]; unsigned len; unsigned char *data; };

int parse_chunk(const unsigned char *buf, size_t n, struct chunk *out) {
    char name[16];
    if (n < 8) return -1;
    memcpy(out->tag, buf, 4);
    out->len = buf[4] | (buf[5] << 8);
    out->data = malloc(out->len);
    memcpy(out->data, buf + 8, out->len);          /* len not checked vs n */
    strcpy(name, (const char *)buf + 8);            /* unbounded copy */
    if (memcmp(out->tag, "eXIf", 4) == 0)
        return parse_exif(out->data, out->len);
    return 0;
}

int parse_exif(const unsigned char *p, unsigned len) {
    char msg[32];
    unsigned i;
    for (i = 0; i <= len; i++) {                   /* off-by-one */
        if (p[i] == 0xff) break;
    }
    sprintf(msg, "exif entries: %u", i);
    return (int)i;
}

void free_chunk(struct chunk *c) {
    free(c->data);
    if (c->len > 1024) free(c->data);               /* double free on big chunks */
}
