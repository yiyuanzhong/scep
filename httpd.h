#ifndef SCEP_HTTPD_H
#define SCEP_HTTPD_H

#include <stdint.h>

#include <openssl/bio.h>

struct httpd;

/* Returns HTTP status code (like 200) */
typedef unsigned int (*httpd_handler_t)(
        void * /* context */,
        const char * /* operation */,
        BIO * /* payload */,
        const char ** /* response content type, statically allocated */,
        BIO * /* response (can be binary), or redirect URL (zero terminated) */
        );

extern struct httpd *httpd_new(
        uint16_t port,
        httpd_handler_t handler,
        void *context);

extern int httpd_start(struct httpd *httpd);
extern int httpd_poll(struct httpd *httpd, sigset_t *sigset);
extern int httpd_stop(struct httpd *httpd);
extern void httpd_free(struct httpd *httpd);

#endif /* SCEP_HTTPD_H */
