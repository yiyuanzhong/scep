#include "httpd.h"

#include <string.h>

#include <errno.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <microhttpd.h>

#include "logger.h"
#include "utils.h"

#define BOOL int
#define TRUE   1
#define FALSE  0

#if MHD_VERSION < 0x00097100
enum MHD_Result { DUMMY };
#define MHD_RESULT int
#else
#define MHD_RESULT enum MHD_Result
#endif

#if   MHD_VERSION < 0x00095300
#define MHD_HTTP_CONTENT_TOO_LARGE MHD_HTTP_REQUEST_ENTITY_TOO_LARGE
#elif MHD_VERSION < 0x00097400
#define MHD_HTTP_CONTENT_TOO_LARGE MHD_HTTP_PAYLOAD_TOO_LARGE
#endif

#if MHD_VERSION < 0x00093400
typedef int MHD_socket;
#define MHD_INVALID_SOCKET (-1)
#endif

struct request {
    BIO *payload;
    BOOL abandoned;
}; /* struct request */

struct httpd {
    struct MHD_Daemon *daemon;
    httpd_handler_t handler;
    void *context;
    uint16_t port;
}; /* struct httpd */

static int httpd_html_escape(
        BIO *bp,
        const char *s,
        BOOL escape_apos)
{
    const char *p;
    size_t needed;
    int ret;

    for (needed = 0, p = s; *p; ++p) {
        switch (*p) {
        case '\'' : needed += escape_apos ? 5 : 1; break;
        case '"'  : needed += 6; break;
        case '&'  : needed += 5; break;
        case '<'  : needed += 4; break;
        case '>'  : needed += 4; break;
        default   : needed += 1; break;
        }
    }

    for (p = s; *p; ++p) {
        switch (*p) {
        case '"' : ret = BIO_write(bp, "&quot;", 6); break;
        case '&' : ret = BIO_write(bp, "&amp;",  5); break;
        case '<' : ret = BIO_write(bp, "&lt;",   4); break;
        case '>' : ret = BIO_write(bp, "&gt;",   4); break;
        case '\'':
            if (escape_apos) {
                ret = BIO_write(bp, "&#39;", 5);
            } else {
                ret = BIO_write(bp, p, 1);
            }
            break;
        default:
            ret = BIO_write(bp, p, 1);
            break;
        };

        if (ret <= 0) {
            return -1;
        }
    }

    return 0;
}

static struct MHD_Response *httpd_create_standard_response(
        unsigned int status_code,
        const char *extra,
        BOOL close)
{
    struct MHD_Response *r;
    const char *status;
    BUF_MEM *bptr;
    BIO *bp;

    switch (status_code) {
    case MHD_HTTP_FOUND:
        status = "Found";
        break;
    case MHD_HTTP_BAD_REQUEST:
        status = "Bad Request";
        break;
    case MHD_HTTP_FORBIDDEN:
        status = "Forbidden";
        break;
    case MHD_HTTP_NOT_FOUND:
        status = "Not Found";
        break;
    case MHD_HTTP_METHOD_NOT_ALLOWED:
        status = "Method Not Allowed";
        break;
    case MHD_HTTP_CONTENT_TOO_LARGE:
        status = "Payload Too Large";
        break;
    case MHD_HTTP_INTERNAL_SERVER_ERROR:
        status = "Internal Server Error";
        break;
    default:
        abort();
    }

    bp = BIO_new(BIO_s_mem());
    if (!bp) {
        return NULL;
    }

    BIO_printf(bp,
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>%u %s</title>\n"
            "</head><body>\n"
            "<h1>%s</h1>\n"
            "<p>", status_code, status, status);

    switch (status_code) {
    case MHD_HTTP_FOUND:
        BIO_printf(bp, "The document has moved <a href=\"");
        httpd_html_escape(bp, extra, TRUE);
        BIO_printf(bp, "\">here</a>.");
        break;

    case MHD_HTTP_BAD_REQUEST:
        BIO_printf(bp, "Your browser sent a request that this server could "
                "not understand.<br />\n");
        break;

    case MHD_HTTP_FORBIDDEN:
        BIO_printf(bp, "You don't have permission to access this resource.");
        break;

    case MHD_HTTP_NOT_FOUND:
        BIO_printf(bp, "The requested URL was not found on this server.");
        break;

    case MHD_HTTP_METHOD_NOT_ALLOWED:
        BIO_printf(bp, "The requested method ");
        httpd_html_escape(bp, extra, FALSE);
        BIO_printf(bp, " is not allowed for this URL.");
        break;

    case MHD_HTTP_CONTENT_TOO_LARGE:
        BIO_printf(bp, "The requested resource does not allow "
                "request data with ");
        httpd_html_escape(bp, extra, FALSE);
        BIO_printf(bp, " requests, or the amount of data provided in\n"
                "the request exceeds the capacity limit.");
        break;

    case MHD_HTTP_INTERNAL_SERVER_ERROR:
        BIO_printf(bp, "The server encountered an internal error or\n"
                "misconfiguration and was unable to complete\n"
                "your request.</p>\n"
                "<p>Please contact the server administrator at \n"
                " ");
        httpd_html_escape(bp, extra, FALSE);
        BIO_printf(bp, " to inform them of the time this error occurred,\n"
                " and the actions you performed just before this error.</p>\n"
                "<p>More information about this error may be available\n"
                "in the server error log.");
        break;

    default:
        abort();
    }

    BIO_printf(bp, "</p>\n</body></html>\n");
    BIO_get_mem_ptr(bp, &bptr);

    r = MHD_create_response_from_buffer(
            bptr->length, bptr->data,
            MHD_RESPMEM_MUST_COPY);

    BIO_free_all(bp);
    if (!r) {
        return NULL;
    }

    if (MHD_add_response_header(r, MHD_HTTP_HEADER_SERVER,
                "Apache") != MHD_YES ||
        MHD_add_response_header(r, MHD_HTTP_HEADER_CONTENT_TYPE,
                "text/html; charset=iso-8859-1") != MHD_YES) {

        MHD_destroy_response(r);
        return NULL;
    }

    if (close) {
        if (MHD_add_response_header(r,
                MHD_HTTP_HEADER_CONNECTION, "close") != MHD_YES) {

            MHD_destroy_response(r);
            return NULL;
        }
    }

    return r;
}

static enum MHD_Result httpd_standard_response(
        struct MHD_Connection *connection,
        unsigned int status_code,
        const char *extra,
        BOOL close)
{
    struct MHD_Response *r;
    enum MHD_Result ret;

    r = httpd_create_standard_response(status_code, extra, close);
    if (!r) {
        return MHD_NO;
    }

    LOGD("http: standard response %u is sent", status_code);
    ret = MHD_queue_response(connection, status_code, r);
    MHD_destroy_response(r);
    return ret;
}

static struct MHD_Response *httpd_create_redirect_response(const char *url)
{
    struct MHD_Response *r;

    r = httpd_create_standard_response(MHD_HTTP_FOUND, url, FALSE);
    if (!r) {
        return NULL;
    }

    if (MHD_add_response_header(r, MHD_HTTP_HEADER_LOCATION, url) != MHD_YES) {
        MHD_destroy_response(r);
        return NULL;
    }

    return r;
}

static enum MHD_Result httpd_redirect(
        struct MHD_Connection *connection,
        const char *url)
{
    struct MHD_Response *r;
    enum MHD_Result ret;

    r = httpd_create_redirect_response(url);
    if (!r) {
        return MHD_NO;
    }

    ret = MHD_queue_response(connection, MHD_HTTP_FOUND, r);
    MHD_destroy_response(r);
    return ret;
}

static enum MHD_Result httpd_error(
        struct MHD_Connection *connection, const char *admin)
{
    return httpd_standard_response(
            connection,
            MHD_HTTP_INTERNAL_SERVER_ERROR,
            admin,
            TRUE);
}

static MHD_RESULT httpd_handler(
        void *cls,
        struct MHD_Connection *connection,
        const char *url,
        const char *method,
        const char *version,
        const char *upload_data,
        size_t *upload_data_size,
        void **con_cls)
{
    static const size_t kMaximum = 1048576;
    struct request *request;
    enum MHD_Result result;
    struct MHD_Response *r;
    const char *operation;
    struct httpd *httpd;
    unsigned int status;
    const char *message;
    const char *rct;
    BUF_MEM *bptr;
    BIO *response;
    int ret;

    (void)url;
    (void)version;

    request = (struct request *)*con_cls;
    if (!request) {
        request = (struct request *)malloc(sizeof(*request));
        if (!request) {
            return MHD_NO;
        }

        memset(request, 0, sizeof(*request));
        request->payload = BIO_new(BIO_s_mem());
        if (!request->payload) {
            free(request);
            return MHD_NO;
        }

        *con_cls = request;
        return MHD_YES;
    }

    if (*upload_data_size) {
        if (request->abandoned) {
            *upload_data_size = 0;
            return MHD_YES;
        } else if (strcmp(method, MHD_HTTP_METHOD_POST)) {
            request->abandoned = TRUE;
            *upload_data_size = 0;
            return MHD_YES;
        }

        BIO_get_mem_ptr(request->payload, &bptr);
        if (bptr->length + *upload_data_size > kMaximum) {
            request->abandoned = TRUE;
            return MHD_YES;
        }

        ret = BIO_write(request->payload, upload_data, *upload_data_size);
        if (ret < 0 || (size_t)ret != *upload_data_size) {
            return MHD_NO;
        }

        *upload_data_size = 0;
        return MHD_YES;

    } else if (request->abandoned) {
        return httpd_standard_response(connection,
                MHD_HTTP_CONTENT_TOO_LARGE,
                method, TRUE);
    }

    operation = MHD_lookup_connection_value(
            connection, MHD_GET_ARGUMENT_KIND, "operation");

    if (!operation || !*operation) {
        return httpd_standard_response(connection,
                MHD_HTTP_BAD_REQUEST,
                NULL, FALSE);
    }

    LOGD("http: %s %s?operation=%s %s", method, url, operation, version);

    if (strcmp(method, MHD_HTTP_METHOD_GET) == 0) {
        message = MHD_lookup_connection_value(
                connection, MHD_GET_ARGUMENT_KIND, "message");

        if (message && *message) {
            if (utils_base64_decode_bio(message, strlen(message), request->payload)) {
                return httpd_error(connection, "admin@example.com");
            }
        }

    } else if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        /* Nothing special about this */

    } else {
        return httpd_standard_response(connection,
                MHD_HTTP_METHOD_NOT_ALLOWED,
                method, FALSE);
    }

    response = BIO_new(BIO_s_mem());
    if (!response) {
        return MHD_NO;
    }

    rct = NULL;
    httpd = (struct httpd *)cls;
    status = httpd->handler(httpd->context, operation,
            request->payload, &rct, response);

    BIO_get_mem_ptr(response, &bptr);
    switch (status) {
    case MHD_HTTP_FOUND:
    case MHD_HTTP_MOVED_PERMANENTLY:
        result = httpd_redirect(connection, bptr->data);
        BIO_free_all(response);
        return result;

    case MHD_HTTP_FORBIDDEN:
    case MHD_HTTP_NOT_FOUND:
    case MHD_HTTP_BAD_REQUEST:
        BIO_free_all(response);
        return httpd_standard_response(connection, status, NULL, FALSE);

    case MHD_HTTP_OK:
        break;

    default:
        BIO_free_all(response);
        return httpd_error(connection, "admin@example.com");
    }

    r = MHD_create_response_from_buffer(
            bptr->length, bptr->data,
            MHD_RESPMEM_MUST_COPY);

    BIO_free_all(response);
    if (!r) {
        return httpd_error(connection, "admin@example.com");
    }

    if (MHD_add_response_header(r, MHD_HTTP_HEADER_SERVER,
                "Apache") != MHD_YES ||
        MHD_add_response_header(r, MHD_HTTP_HEADER_CACHE_CONTROL,
                "private, no-cache, no-store, must-revalidate, "
                "max-age=0") != MHD_YES ||
        MHD_add_response_header(r, MHD_HTTP_HEADER_PRAGMA,
                "no-cache") != MHD_YES ||
        (rct && MHD_add_response_header(r, MHD_HTTP_HEADER_CONTENT_TYPE,
                rct) != MHD_YES) ){

        MHD_destroy_response(r);
        return httpd_error(connection, "admin@example.com");
    }

    result = MHD_queue_response(connection, status, r);
    LOGD("http: user response (%s) is sent", rct);
    MHD_destroy_response(r);
    return result;
}

static void httpd_completed(
        void *cls,
        struct MHD_Connection *connection,
        void **con_cls,
        enum MHD_RequestTerminationCode toe)
{
    struct request *request;

    (void)cls;
    (void)connection;
    (void)toe;

    request = (struct request *)(*con_cls);
    BIO_free_all(request->payload);
    free(request);
}

struct httpd *httpd_new(uint16_t port, httpd_handler_t handler, void *context)
{
    struct httpd *httpd;

    if (!port || !handler) {
        return NULL;
    }

    httpd = (struct httpd *)malloc(sizeof(*httpd));
    if (!httpd) {
        return NULL;
    }

    memset(httpd, 0, sizeof(*httpd));
    httpd->handler = handler;
    httpd->context = context;
    httpd->port = port;
    return httpd;
}

int httpd_start(struct httpd *httpd)
{
    const unsigned int flags = MHD_USE_DUAL_STACK;

    httpd->daemon = MHD_start_daemon(
            flags, httpd->port, NULL, NULL,
            httpd_handler, httpd,
            MHD_OPTION_NOTIFY_COMPLETED,
            httpd_completed, httpd,
            MHD_OPTION_END);

    if (!httpd->daemon) {
        return -1;
    }

    return 0;
}

int httpd_poll(struct httpd *httpd, sigset_t *sigset)
{
    fd_set rset;
    fd_set wset;
    fd_set eset;
    int max;
    int ret;

    max = -1;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_ZERO(&eset);
    if (MHD_get_fdset(httpd->daemon, &rset, &wset, &eset, &max) != MHD_YES) {
        return -1;
    }

    ret = pselect(max + 1, &rset, &wset, &eset, NULL, sigset);
    if (ret < 0) {
        if (errno != EINTR) {
            return -1;
        }
        return 0;
    } else if (ret == 0) {
        return 0;
    }

    if (MHD_run_from_select(httpd->daemon, &rset, &wset, &eset) != MHD_YES) {
        return -1;
    }

    return 0;
}

int httpd_stop(struct httpd *httpd)
{
    MHD_socket listener;

    listener = MHD_quiesce_daemon(httpd->daemon);
    MHD_stop_daemon(httpd->daemon);
    if (listener != MHD_INVALID_SOCKET) {
        close(listener);
    }

    httpd->daemon = NULL;
    return 0;
}

void httpd_free(struct httpd *httpd)
{
    free(httpd);
}
