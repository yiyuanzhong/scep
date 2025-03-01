#include "utils.h"

#include <string.h>

#include <openssl/buffer.h>
#include <openssl/evp.h>

int utils_base64_decode_bio(const void *input, size_t ilen, BIO *bp)
{
    unsigned char buffer[256];
    BIO *bmem;
    BIO *b64;
    int ret;

    bmem = BIO_new_mem_buf(input, ilen);
    if (!bmem) {
        return -1;
    }

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        BIO_free_all(bmem);
        return -1;
    }

    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    for (;;) {
        ret = BIO_read(b64, buffer, sizeof(buffer));
        if (ret < 0) {
            BIO_free_all(b64);
            return -1;
        } else if (ret == 0) {
            break;
        }

        if (BIO_write(bp, buffer, ret) != ret) {
            BIO_free_all(b64);
            return -1;
        }
    }

    BIO_free_all(b64);
    return 0;
}

ssize_t utils_base64_decode(
        const void *input, size_t ilen,
        unsigned char *output, size_t olen)
{
    BUF_MEM *bptr;
    ssize_t ret;
    BIO *bout;

    if ((ilen + 3) / 4 > olen / 3) {
        return -1;
    }

    bout = BIO_new(BIO_s_mem());
    if (!bout) {
        return -1;
    }

    if (utils_base64_decode_bio(input, ilen, bout)) {
        BIO_free_all(bout);
        return -1;
    }

    BIO_get_mem_ptr(bout, &bptr);
    if ((ret = bptr->length)) {
        memcpy(output, bptr->data, bptr->length);
    }

    BIO_free_all(bout);
    return ret;
}
