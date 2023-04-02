#include <string.h>

#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <microhttpd.h>

#include "httpd.h"
#include "scep.h"

#ifndef static_assert
#define static_assert(x) _Static_assert((x), #x)
#endif

struct context {
    const char *challenge_password;
    long allow_renew_days;
    long validity_days;
    const char *depot;
    struct scep *scep;
};

struct token {
    uint32_t timestamp;
    uint32_t nonce;
    unsigned char hmac[32];
};
static_assert(sizeof(struct token) == 40);

static volatile sig_atomic_t g_quit;

static void on_signal_quit(int signum)
{
    g_quit = signum;
}

static int validate_validity(time_t now, const X509 *x509, long days)
{
    const ASN1_TIME *when;
    ASN1_TIME *ts;

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

static void hex(const void *input, size_t inlen, char *output)
{
    static const char H[] = "0123456789ABCDEF";
    const unsigned char *p;
    size_t i;

    p = (const unsigned char *)input;
    for (i = 0; i < inlen; ++i) {
        output[i * 2 + 0] = H[p[i] / 16];
        output[i * 2 + 1] = H[p[i] % 16];
    }
}

static int unhex_one(const char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return -1;
    }
}

static int unhex(const void *input, size_t inlen, void *output)
{
    unsigned char *o;
    const char *p;
    size_t i;
    int h;
    int l;

    if (inlen % 2) {
        return -1;
    }

    p = (const char *)input;
    o = (unsigned char *)output;
    for (i = 0; i < inlen; i += 2) {
        h = unhex_one(p[i + 0]);
        l = unhex_one(p[i + 1]);
        if (h < 0 || l < 0) {
            return -1;
        }

        *o++ = (unsigned char)(h * 16 + l);
    }

    return 0;
}

static int parse_name(X509_NAME *name, char *subject, int strict)
{
    char *value;
    int escape;
    char *key;
    char *q;
    char *p;

    p = subject;
    if (*p++ != '/') {
        return -1;
    }

    for (;;) {
        key = strsep(&p, "=");
        if (!key || !p) {
            return -1;
        }

        for (value = q = p, escape = 0; *p; ++p) {
            if (escape) {
                *q++ = *p;
                escape = 0;

            } else if (*p == '/') {
                break;

            } else if (*p == '\\') {
                if (escape || !p[1]) {
                    return -1;
                }
                escape = 1;

            } else {
                *q++ = *p;
            }
        }

        if (!*key || !*value) {
            if (strict) {
                return -1;
            }

            continue;
        }

        if (X509_NAME_add_entry_by_txt(name, key, MBSTRING_ASC,
                (unsigned char *)value, q - value, -1, 0) != 1) {

            return -1;
        }

        if (*p) {
            ++p;
        } else {
            break;
        }
    }

    return 0;
}

static int hash(const EVP_MD *md, const char *what, unsigned char *output)
{
    unsigned int hlen;
    EVP_MD_CTX *ctx;
    size_t length;

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    length = strlen(what);
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1       ||
        EVP_DigestUpdate(ctx, what, length) != 1    ||
        EVP_DigestFinal_ex(ctx, output, &hlen) != 1 ){

        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

static int generate_challenge_password(
        const char *secret,
        time_t timestamp,
        uint32_t nonce,
        const X509_NAME *name,
        char *output)
{
    unsigned char key[SHA256_DIGEST_LENGTH];
    struct token token;
    unsigned int hlen;
    BUF_MEM *bptr;
    HMAC_CTX *ctx;
    BIO *bp;

    if (hash(EVP_sha256(), secret, key)) {
        return -1;
    }

    ctx = HMAC_CTX_new();
    if (!ctx) {
        return -1;
    }

    bp = BIO_new(BIO_s_mem());
    if (!bp) {
        HMAC_CTX_free(ctx);
        return -1;
    }

    if (X509_NAME_print_ex(bp, name, 0, XN_FLAG_RFC2253) == -1) {
        BIO_free_all(bp);
        HMAC_CTX_free(ctx);
        return -1;
    }

    BIO_get_mem_ptr(bp, &bptr);
    memset(&token, 0, sizeof(token));
    token.timestamp = timestamp;
    token.nonce = nonce;

    if (HMAC_Init_ex(ctx, key, sizeof(key), EVP_sha256(), NULL) != 1          ||
        HMAC_Update(ctx, (unsigned char *)&timestamp, sizeof(timestamp)) != 1 ||
        HMAC_Update(ctx, (unsigned char *)&nonce, sizeof(nonce)) != 1         ||
        HMAC_Update(ctx, (unsigned char *)bptr->data, bptr->length) != 1      ||
        HMAC_Final(ctx, token.hmac, &hlen) != 1                               ){

        HMAC_CTX_free(ctx);
        BIO_free_all(bp);
        return -1;
    }

    HMAC_CTX_free(ctx);
    BIO_free_all(bp);

    hex(&token, sizeof(token), output);
    output[sizeof(token) * 2] = '\0';
    return 0;
}

static int generate_challenge_password_from_subject(
        const char *secret,
        uint32_t timestamp,
        uint32_t nonce,
        const char *subject,
        char *output)
{
    X509_NAME *name;
    char *copy;

    copy = strdup(subject);
    if (!copy) {
        return -1;
    }

    name = X509_NAME_new();
    if (!name) {
        free(copy);
        return -1;
    }

    if (parse_name(name, copy, 1)) {
        X509_NAME_free(name);
        free(copy);
        return -1;
    }

    free(copy);
    if (generate_challenge_password(secret, timestamp, nonce, name, output)) {
        X509_NAME_free(name);
        return -1;
    }

    X509_NAME_free(name);
    return 0;
}

static int validate_cp(
        time_t now,
        struct context *ctx,
        const X509_REQ *csr,
        const ASN1_PRINTABLESTRING *cp)
{
    static const uint32_t kValid = 604800; /* 7 days */

    char output[sizeof(struct token) * 2 + 1];
    const X509_NAME *subject;
    struct token token;
    uint32_t timestamp;

    if (!ctx->challenge_password || !*ctx->challenge_password) {
        fprintf(stderr, "DEBUG: no challenge succeeded\n");
        return 1;
    }

    if (cp->length != sizeof(token) * 2) {
        return 0;
    }

    if (unhex(cp->data, cp->length, &token)) {
        return 0;
    }

    subject = X509_REQ_get_subject_name(csr);
    if (generate_challenge_password(ctx->challenge_password,
            token.timestamp, token.nonce, subject, output)) {

        return -1;
    }

    if (memcmp(output, cp->data, sizeof(token) * 2)) {
        return 0;
    }

    if (now > UINT32_MAX) { /* Ahh? */
        return -1;
    }

    timestamp = (uint32_t)now;
    if (token.timestamp > timestamp || timestamp - token.timestamp > kValid) {
        return 0;
    }

    fprintf(stderr, "DEBUG: good challenge succeeded\n");
    return 1;
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
        time_t now,
        struct context *ctx,
        const X509_REQ *csr,
        const ASN1_PRINTABLESTRING *cp,
        const X509 *signer)
{
    int ret;

    /* The idea is to check subject and SAN together with challenge password,
     * but since I haven't implemented authenticated challenge passwords for
     * SAN, only subject is being checked */

    if (!ctx->challenge_password || !*ctx->challenge_password) {
        fprintf(stderr, "DEBUG: no challenge succeeded\n");
        return 1;
    }

    if (cp) {
        ret = validate_cp(now, ctx, csr, cp);
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

    ret = validate_validity(now, signer, ctx->allow_renew_days);
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
    int num;

    (void)payload;

    num = scep_get_cert(ctx->scep, response);

    if (num <= 0) {
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (num == 1) {
        *rct = "application/x-x509-ca-cert";
    } else {
        *rct = "application/x-x509-ca-ra-cert";
    }

    return MHD_HTTP_OK;
}

static int save_subject(const char *depot, struct scep_CertRep *rep)
{
    const ASN1_INTEGER *sn;
    char file[PATH_MAX];
    X509 *subject;
    char *serial;
    BIGNUM *bn;
    BIO *bp;
    int ret;

    subject = scep_CertRep_get_subject(rep);
    if (!subject) {
        return -1;
    }

    sn = X509_get0_serialNumber(subject);
    if (!sn) {
        return -1;
    }

    bn = ASN1_INTEGER_to_BN(sn, NULL);
    if (!bn) {
        return -1;
    }

    serial = BN_bn2hex(bn);
    if (!serial) {
        BN_free(bn);
        return -1;
    }

    BN_free(bn);

    ret = snprintf(file, sizeof(file), "%s/%s.pem", depot, serial);
    if (ret < 0 || (size_t)ret >= sizeof(file)) {
        OPENSSL_free(serial);
        return -1;
    }

    OPENSSL_free(serial);

    bp = BIO_new_file(file, "wb");
    if (!bp) {
        return -1;
    }

    if (PEM_write_bio_X509(bp, subject) != 1) {
        BIO_free_all(bp);
        unlink(file);
        return -1;
    }

    BIO_free_all(bp);
    return 0;
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
    time_t now;
    int ret;

    now = time(NULL);
    scep = ctx->scep;

    m = scep_pkiMessage_new(scep, payload);
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

    ret = validate(now, ctx, csr, cp, signer);
    if (ret < 0) {
        scep_PKCSReq_free(req);
        scep_pkiMessage_free(m);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;

    } else if (ret == 0) {
        rep = scep_CertRep_reject(scep, req, failInfo_badRequest);

    } else {
        rep = scep_CertRep_new(scep, req, now, ctx->validity_days);
    }

    if (!rep) {
        scep_PKCSReq_free(req);
        scep_pkiMessage_free(m);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    scep_PKCSReq_free(req);
    scep_pkiMessage_free(m);
    if (ret > 0) {
        if (ctx->depot && *ctx->depot) {
            if (save_subject(ctx->depot, rep)) {
                scep_CertRep_free(rep);
                return MHD_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (scep_CertRep_save(rep, response)) {
        scep_CertRep_free(rep);
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    scep_CertRep_free(rep);

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
                      " [-d /some/where/depot]"
                      " [-R allow_renew_days=14]"
                      " [-e extension.cnf]\n", argv);

    fprintf(stderr, "%s <-C challenge>"
                      " <-S /O=US/CN=test>\n", argv);

    fprintf(stderr, "%s <-h>\n", argv);

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

static int main_generate(const char *subject, const char *key)
{
    char output[sizeof(struct token) * 2 + 1];
    uint32_t timestamp;
    uint32_t nonce;
    time_t now;

    now = time(NULL);
    if (now > UINT32_MAX) { /* Ahh? */
        return EXIT_FAILURE;
    }

    timestamp = (uint32_t)now;
    if (RAND_bytes((unsigned char *)&nonce, sizeof(nonce)) != 1) {
        return EXIT_FAILURE;
    }

    if (generate_challenge_password_from_subject(
            key, timestamp, nonce, subject, output)) {

        return EXIT_FAILURE;
    }

    fprintf(stderr, "DEBUG: timestamp=%u\n", timestamp);
    fprintf(stderr, "DEBUG: nonce=%u\n", nonce);
    printf("%s\n", output);
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    struct scep_configure configure;
    struct httpd *httpd;
    struct context ctx;
    struct scep *scep;
    sigset_t empty;
    uint16_t port;
    int exposed;
    size_t i;
    int cfrm;
    int lfrm;
    int kfrm;
    int ret;
    int c;

    static const char *kOptString = "p:c:k:f:F:P:C:V:R:S:d:e:l:L:Eh";
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
        { "subject",    required_argument, NULL, 'S' },
        { "depot",      required_argument, NULL, 'd' },
        { "extensions", required_argument, NULL, 'e' },
        { "chain",      required_argument, NULL, 'l' },
        { "chainform",  required_argument, NULL, 'L' },
        { "exposed_cp", no_argument,       NULL, 'E' },
        { "help",       no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    const char *arg_port = NULL;
    const char *arg_cert = NULL;
    const char *arg_pkey = NULL;
    const char *arg_pass = NULL;
    const char *arg_chlg = NULL;
    const char *arg_sjct = NULL;
    const char *arg_exts = NULL;
    const char *arg_dpot = NULL;

    const char *arg_link[8];
    const char *arg_lfrm[8];
    size_t arg_links;

    const char *arg_days = "90";
    const char *arg_renw = "14";
    const char *arg_cfrm = "pem";
    const char *arg_kfrm = "pem";

    exposed = 0;
    arg_links = 0;
    for (i = 0; i < sizeof(arg_link) / sizeof(*arg_link); ++i) {
        arg_lfrm[i] = "pem";
    }

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
        case 'S': arg_sjct = optarg; break;
        case 'd': arg_dpot = optarg; break;
        case 'e': arg_exts = optarg; break;
        case 'E': exposed  =      1; break;

        case 'L': arg_lfrm[arg_links] = optarg; break;
        case 'l':
            if (arg_links + 1 == sizeof(arg_link) / sizeof(*arg_link)) {
                fprintf(stderr, "Too long certificate chain\n");
                return EXIT_FAILURE;
            }
            arg_link[arg_links++] = optarg;
            break;

        default : return help(argv[0]);
        }
    }

    if (arg_sjct && arg_chlg) {
        return main_generate(arg_sjct, arg_chlg);
    }

    if (!arg_port || !arg_cert || !arg_pkey || optind < argc) {
        return help(argv[0]);
    }

    memset(&ctx, 0, sizeof(ctx));
    memset(&configure, 0, sizeof(configure));

    ctx.depot = arg_dpot;
    ctx.challenge_password = arg_chlg;
    configure.tolerate_exposed_challenge_password = exposed;

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

    scep = scep_new(&configure);
    if (!scep) {
        return EXIT_FAILURE;
    }

    if (scep_load_certificate(scep,
            arg_cert, cfrm, arg_pkey, kfrm, arg_pass)) {

        scep_free(scep);
        return EXIT_FAILURE;
    }

    for (i = 0; i < arg_links; ++i) {
        if (atoform(arg_lfrm[i], &lfrm)) {
            return help(argv[0]);
        }

        if (scep_load_certificate_chain(scep, arg_link[i], lfrm)) {
            scep_free(scep);
            return EXIT_FAILURE;
        }
    }

    if (arg_exts) {
        if (scep_load_subject_extensions(scep, arg_exts)) {
            scep_free(scep);
            return EXIT_FAILURE;
        }
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
