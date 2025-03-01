#ifndef SCEP_UTILS_H
#define SCEP_UTILS_H

#include <openssl/bio.h>

extern int utils_base64_decode_bio(const void *input, size_t ilen, BIO *bp);

extern ssize_t utils_base64_decode(
        const void *input, size_t ilen,
        unsigned char *o, size_t olen);

#endif /* SCEP_UTILS_H */
