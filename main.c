#include <string.h>

#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/x509.h>

#include <microhttpd.h>

#include "httpd.h"
#include "scep.h"

struct context {
    int allow_exposed_challenge_password;
    const char *challenge_password;
    long allow_renew_days;
    long validity_days;
    struct scep *scep;
};

static volatile sig_atomic_t g_quit;

static void on_signal_quit(int signum)
{
    g_quit = signum;
}

static int validate_validity(const X509 *x509, long days)
{
    const ASN1_TIME *when;
    ASN1_TIME *ts;
    time_t now;

    now = time(NULL);

    when = X509_get0_notBefore(x509);
    if (ASN1_TIME_cmp_time_t(when, now) > 0) {
        return 0;
    }

    when = X509_get0_notAfter(x509);
    if (days > 0) {
        ts = ASN1_TIME_new();
        if (!ts) {
            return -1;
        }

        if (!ASN1_TIME_adj(ts, now, days, 0)) {
            ASN1_TIME_free(ts);
            return -1;
        }

        if (ASN1_TIME_cmp_time_t(when, now) < 0 || /* Expired */
            ASN1_TIME_compare(when, ts) > 0     ){ /* Still valid */

            ASN1_TIME_free(ts);
            return 0;
        }

        fprintf(stderr, "DEBUG: good renewal\n");
        ASN1_TIME_free(ts);

    } else {
        if (ASN1_TIME_cmp_time_t(when, now) < 0) { /* Expired */
            return 0;
        }

        fprintf(stderr, "DEBUG: good anytime renewal\n");
    }

    return 1;
 }

static int validate_cp(
        struct context *ctx,
        const X509_REQ *csr,
        const ASN1_PRINTABLESTRING *cp)
{
    const X509_NAME *subject;
    BUF_MEM *bptr;
    size_t len;
    BIO *bp;
    int ret;

    if (!ctx->challenge_password || !*ctx->challenge_password) {
        fprintf(stderr, "DEBUG: no challenge succeeded\n");
        return 1;
    }

    subject = X509_REQ_get_subject_name(csr);
    bp = BIO_new(BIO_s_mem());
    if (!bp) {
        return -1;
    }

    if (X509_NAME_print_ex(bp, subject, 0, XN_FLAG_RFC2253) == -1) {
        BIO_free_all(bp);
        return -1;
    }

    BIO_get_mem_ptr(bp, &bptr);

    ret = 0;
    len = strlen(ctx->challenge_password);
    if ((size_t)cp->length == len                           &&
        memcmp(cp->data, ctx->challenge_password, len) == 0 ){

        fprintf(stderr, "DEBUG: good challenge succeeded\n");
        ret = 1;
    }

    BIO_free_all(bp);
    return ret;
}

static int validate_subject(const X509_REQ *csr, const X509 *signer)
{
    int ret;

    ret = X509_NAME_cmp(X509_REQ_get_subject_name(csr),
                        X509_get_subject_name(signer));

    if (ret == -2) {
        return -1;
    } else if (ret) {
        return 0;
    } else {
        return 1;
    }
}

static int validate(
        struct context *ctx,
        const X509_REQ *csr,
        const ASN1_PRINTABLESTRING *cp,
        const X509 *signer)
{
    int ret;

    /* The idea is to check subject and SAN together with challenge password,
     * but since I haven't implemented authenticated challenge passwords the
     * two fields are not checked at all */

    if (cp) {
        ret = validate_cp(ctx, csr, cp);
        if (ret) {
            return ret;
        }
    }

    if (!signer) {
        return 0;
    }

    ret = validate_subject(csr, signer);
    if (ret <= 0) {
        return ret;
    }

    /* I should check if SAN matches here as well */

    ret = validate_validity(signer, ctx->allow_renew_days);
    if (ret <= 0) {
        return ret;
    }

    return 1;
}

static unsigned int handle_GetCACaps(
        struct context *ctx,
        BIO *payload,
        const char **rct,
        BIO *response)
{
    (void)ctx;
    (void)payload;

    *rct = "text/plain";
    BIO_printf(response,
            "AES\n"
            "POSTPKIOperation\n"
            "Renewal\n"
            "SHA-256\n"
            "SHA-512\n"
            "SCEPStandard");
    return MHD_HTTP_OK;
}

static unsigned int handle_GetCACert(
        struct context *ctx,
        BIO *payload,
        const char **rct,
        BIO *response)
{
    (void)payload;

    if (scep_get_cert(ctx->scep, response)) {
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    *rct = "application/x-x509-ca-cert";
    return MHD_HTTP_OK;
}

static unsigned int handle_PKIOperation(
        struct context *ctx,
        BIO *payload,
        const char **rct,
        BIO *response)
{
    const ASN1_PRINTABLESTRING *cp;
    struct scep_pkiMessage *m;
    struct scep_PKCSReq *req;
    struct scep_CertRep *rep;
    const X509_REQ *csr;
    const X509 *signer;
    struct scep *scep;
    int ret;

    scep = ctx->scep;

    m = scep_pkiMessage_new(scep, payload,
            ctx->allow_exposed_challenge_password);

    if (!m) {
        return MHD_HTTP_BAD_REQUEST;
    }

    switch (scep_pkiMessage_get_type(m)) {
    case messageType_PKCSReq:
        break;
    default:
        scep_pkiMessage_free(m);
        return MHD_HTTP_BAD_REQUEST;
    }

    req = scep_PKCSReq_new(scep, m);
    if (!req) {
        scep_pkiMessage_free(m);
        return MHD_HTTP_BAD_REQUEST;
    }

    csr = scep_PKCSReq_get_csr(req);
    cp = scep_PKCSReq_get_challengePassword(req);
    signer = scep_PKCSReq_get_current_certificate(req);

    ret = validate(ctx, csr, cp, signer);
    if (ret < 0) {
        scep_PKCSReq_free(req);
        scep_pkiMessage_free(m);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;

    } else if (ret == 0) {
        rep = scep_CertRep_reject(scep, req, failInfo_badRequest);

    } else {
        rep = scep_CertRep_new(scep, req, ctx->validity_days);
    }

    if (!rep) {
        scep_PKCSReq_free(req);
        scep_pkiMessage_free(m);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    scep_PKCSReq_free(req);
    if (scep_CertRep_save(rep, response)) {
        scep_CertRep_free(rep);
        scep_pkiMessage_free(m);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    scep_CertRep_free(rep);
    scep_pkiMessage_free(m);

    *rct = "application/x-pki-message";
    return MHD_HTTP_OK;
}

static unsigned int handle(
        void *context,
        const char *operation,
        BIO *payload,
        const char **rct,
        BIO *response)
{
    struct context *ctx;

    ctx = (struct context *)context;
    if (strcmp(operation, "GetCACaps") == 0) {
        return handle_GetCACaps(ctx, payload, rct, response);
    } else if (strcmp(operation, "GetCACert") == 0) {
        return handle_GetCACert(ctx, payload, rct, response);
    } else if (strcmp(operation, "PKIOperation") == 0) {
        return handle_PKIOperation(ctx, payload, rct, response);
    } else {
        return MHD_HTTP_BAD_REQUEST;
    }
}

static int initialize_signals(void)
{
    struct sigaction sa;
    sigset_t sigset;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal_quit;

    if (sigfillset(&sigset)                     ||
        sigprocmask(SIG_BLOCK, &sigset, NULL)   ||
        sigaction(SIGHUP, &sa, NULL)            ||
        sigaction(SIGINT, &sa, NULL)            ||
        sigaction(SIGTERM, &sa, NULL)           ||
        sigemptyset(&sigset)                    ||
        sigaddset(&sigset, SIGINT)              ||
        sigaddset(&sigset, SIGHUP)              ||
        sigaddset(&sigset, SIGTERM)             ||
        sigprocmask(SIG_SETMASK, &sigset, NULL) ){

        return -1;
    }

    return 0;
}

static int help(const char *argv)
{
    fprintf(stderr, "%s <-p port>"
                      " <-c certificate> [-f PEM|DER=PEM]"
                      " <-k pkey> [-F PEM|DER=PEM]"
                      " [-P pass] [-C challenge]"
                      " [-V validity_days=90]"
                      " [-R allow_renew_days=14]"
                      " [-h]\n", argv);

    return EXIT_FAILURE;
}

static int atoport(const char *s, uint16_t *p)
{
    unsigned long n;
    char *end;

    n = strtoul(s, &end, 10);
    if (*end || !n || n > UINT16_MAX) {
        return -1;
    }

    *p = (uint16_t)n;
    return 0;
}

static int atodays(const char *s, long *d)
{
    char *end;
    long n;

    if (!s) {
        return 0;
    }

    n = strtol(s, &end, 10);
    if (*end || n < 0 || n > INT16_MAX) {
        return -1;
    }

    *d = n;
    return 0;
}

static int atoform(const char *s, int *f)
{
    if (!s) {
        return 0;
    } else if (strcasecmp(s, "pem") == 0) {
        *f = 1;
        return 0;
    } else if (strcasecmp(s, "der") == 0) {
        *f = 0;
        return 0;
    } else {
        return -1;
    }
}

int main(int argc, char *argv[])
{
    struct httpd *httpd;
    struct context ctx;
    struct scep *scep;
    sigset_t empty;
    uint16_t port;
    int exposed;
    int cfrm;
    int kfrm;
    int ret;
    int c;

    static const char *kOptString = "p:c:k:f:F:P:C:V:R:Eh";
    static const struct option kLongOpts[] = {
        { "port",       required_argument, NULL, 'p' },
        { "ca",         required_argument, NULL, 'c' },
        { "key",        required_argument, NULL, 'k' },
        { "caform",     required_argument, NULL, 'f' },
        { "keyform",    required_argument, NULL, 'F' },
        { "capass",     required_argument, NULL, 'P' },
        { "challenge",  required_argument, NULL, 'C' },
        { "days",       required_argument, NULL, 'V' },
        { "allowrenew", required_argument, NULL, 'R' },
        { "exposed_cp", no_argument,       NULL, 'E' },
        { "help",       no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    const char *arg_port = NULL;
    const char *arg_cert = NULL;
    const char *arg_pkey = NULL;
    const char *arg_pass = NULL;
    const char *arg_chlg = NULL;
    const char *arg_days = "90";
    const char *arg_renw = "14";
    const char *arg_cfrm = "pem";
    const char *arg_kfrm = "pem";

    exposed = 0;
    while ((c = getopt_long(argc, argv, kOptString, kLongOpts, NULL)) != -1) {
        switch (c) {
        case 'p': arg_port = optarg; break;
        case 'c': arg_cert = optarg; break;
        case 'k': arg_pkey = optarg; break;
        case 'P': arg_pass = optarg; break;
        case 'C': arg_chlg = optarg; break;
        case 'V': arg_days = optarg; break;
        case 'R': arg_renw = optarg; break;
        case 'f': arg_cfrm = optarg; break;
        case 'F': arg_kfrm = optarg; break;
        case 'E': exposed  =      1; break;
        default : return help(argv[0]);
        }
    }

    if (!arg_port || !arg_cert || !arg_pkey || optind < argc) {
        return help(argv[0]);
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.challenge_password = arg_chlg;
    ctx.allow_exposed_challenge_password = exposed;
    if (atoport(arg_port, &port)                 ||
        atodays(arg_days, &ctx.validity_days)    ||
        atodays(arg_renw, &ctx.allow_renew_days) ||
        atoform(arg_cfrm, &cfrm)                 ||
        atoform(arg_kfrm, &kfrm)                 ){

        return help(argv[0]);
    }


    if (sigemptyset(&empty) ||initialize_signals()) {
        return EXIT_FAILURE;
    }

    scep = scep_new();
    if (!scep) {
        return EXIT_FAILURE;
    }

    if (scep_load_certificate(scep,
            arg_cert, cfrm, arg_pkey, kfrm, arg_pass)) {

        scep_free(scep);
        return EXIT_FAILURE;
    }

    ctx.scep = scep;
    httpd = httpd_new(port, handle, &ctx);
    if (!httpd) {
        scep_free(scep);
        return EXIT_FAILURE;
    }

    if (httpd_start(httpd)) {
        httpd_free(httpd);
        scep_free(scep);
        return EXIT_FAILURE;
    }

    ret = 0;
    while (!g_quit) {
        if (httpd_poll(httpd, &empty)) {
            ret = -1;
            break;
        }
    }

    httpd_stop(httpd);
    httpd_free(httpd);
    scep_free(scep);
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
