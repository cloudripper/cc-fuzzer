#include <stddef.h>
#include <stdint.h>
int encode_chunk(const unsigned char *, size_t, void *);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    encode_chunk(data, size, 0);
    return 0;
}
