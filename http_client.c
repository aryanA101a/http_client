#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <err.h>
#include <errno.h>
#include <time.h>

#include "bearssl.h"
#include "trust_anchors.inc"

#define PROTO_LENGTH 6
#define HOST_LENGTH 254
#define PORT_LENGTH 6
#define PATH_LENGTH 4096

#define URL_LENGTH (PROTO_LENGTH + 3 + HOST_LENGTH + 1 + PORT_LENGTH + PATH_LENGTH)

#define MAX_REDIRECTS 5
#define MAX_INFO_RESPONSES 10

// should be initialized by {null,0,0} if not allocated at the initialization
typedef struct
{
    char *buffer;
    size_t capacity;
    size_t size;
} buf;

typedef struct url
{
    char protocol[PROTO_LENGTH];
    char hostname[HOST_LENGTH];
    char port[PORT_LENGTH];
    char path[PATH_LENGTH];
} url_t;

typedef struct
{
    br_ssl_client_context client;
    br_x509_minimal_context x509;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
} tls_ctx;

typedef struct conn conn_t;

struct conn
{
    int fd;
    tls_ctx tls;

    ssize_t (*read)(conn_t *conn, void *buf, size_t len, int timeout_ms);
    ssize_t (*write)(conn_t *conn, const void *buf, size_t len,
                     int timeout_ms);
    int (*close)(conn_t *conn);
};

typedef struct sink
{
    int (*write)(struct sink *s, const void *data, size_t len);
} sink_t;

typedef struct
{
    sink_t *sink;
    const char *url;
    void (*on_progress)(size_t received, size_t total);
} http_req_t;

typedef struct
{
    ssize_t content_length;
    int chunked;
    int has_location;
    char location[URL_LENGTH];
} http_headers_t;

typedef enum
{
    HTTP_OK = 0,
    HTTP_ERR_USAGE = 2,
    HTTP_ERR_URL_INVALID = 10,
    HTTP_ERR_CONNECT = 11,
    HTTP_ERR_IO = 12,
    HTTP_ERR_REQUEST_TOO_LARGE = 13,
    HTTP_ERR_STATUS_INVALID_LINE = 20,
    HTTP_ERR_RESPONSE_UNSUPPORTED = 21,
    HTTP_ERR_HEADER_MALFORMED = 30,
    HTTP_ERR_HEADER_INVALID_CONTENT_LENGTH = 31,
    HTTP_ERR_HEADER_UNSUPPORTED_TRANSFER_ENCODING = 32,
    HTTP_ERR_BODY_INVALID_CHUNK_SIZE = 40,
    HTTP_ERR_BODY_TRUNCATED = 41,
    HTTP_ERR_RESPONSE_SERVER_ERROR = 50,
    HTTP_ERR_RESPONSE_CLIENT_ERROR = 51
} http_error_t;

const char *http_error_name(http_error_t err)
{
    switch (err)
    {
    case HTTP_OK:
        return "ok";
    case HTTP_ERR_USAGE:
        return "usage";
    case HTTP_ERR_URL_INVALID:
        return "url.invalid";
    case HTTP_ERR_CONNECT:
        return "connect";
    case HTTP_ERR_IO:
        return "io";
    case HTTP_ERR_REQUEST_TOO_LARGE:
        return "request.too_large";
    case HTTP_ERR_STATUS_INVALID_LINE:
        return "status.invalid_line";
    case HTTP_ERR_RESPONSE_UNSUPPORTED:
        return "response.unsupported";
    case HTTP_ERR_HEADER_MALFORMED:
        return "header.malformed";
    case HTTP_ERR_HEADER_INVALID_CONTENT_LENGTH:
        return "header.invalid_content_length";
    case HTTP_ERR_HEADER_UNSUPPORTED_TRANSFER_ENCODING:
        return "header.unsupported_transfer_encoding";
    case HTTP_ERR_BODY_INVALID_CHUNK_SIZE:
        return "body.invalid_chunk_size";
    case HTTP_ERR_BODY_TRUNCATED:
        return "body.truncated";
    case HTTP_ERR_RESPONSE_SERVER_ERROR:
        return "server.error";
    case HTTP_ERR_RESPONSE_CLIENT_ERROR:
        return "client.error";
    }

    return "unknown";
}

int http_fail(http_error_t err, const char *detail)
{
    fprintf(stderr, "http_client: %s", http_error_name(err));
    if (detail != NULL && detail[0] != '\0')
        fprintf(stderr, ": %s", detail);
    fputc('\n', stderr);

    return (int)err;
}

int64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;

    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int64_t
deadline_after(int timeout_ms)
{
    int64_t start_ms;

    if (timeout_ms < 0)
    {
        errno = EINVAL;
        return -1;
    }

    start_ms = now_ms();
    if (start_ms < 0)
        return -1;

    return start_ms + timeout_ms;
}

static int
wait_for_socket(int fd, short events, int64_t deadline)
{
    struct pollfd pfd = {
        .fd = fd,
        .events = events};

    for (;;)
    {
        int64_t cur_ms = now_ms();
        if (cur_ms < 0)
            return -1;
        if (cur_ms >= deadline)
        {
            errno = ETIMEDOUT;
            return -1;
        }

        int64_t remaining_ms = deadline - cur_ms;
        int timeout_ms = remaining_ms < 250 ? (int)remaining_ms : 250;
        int n = poll(&pfd, 1, timeout_ms);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            continue;
        if (pfd.revents & POLLNVAL)
        {
            errno = EBADF;
            return -1;
        }
        if (pfd.revents & (POLLERR | POLLHUP))
            pfd.revents |= POLLIN | POLLOUT;

        return pfd.revents;
    }
}

static int
run_brssl_engine(conn_t *conn, unsigned int target, int timeout_ms)
{
    br_ssl_engine_context *engine;
    int64_t deadline;

    if (conn == NULL || conn->fd < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (target != BR_SSL_SENDAPP && target != BR_SSL_RECVAPP)
    {
        errno = EINVAL;
        return -1;
    }
    deadline = deadline_after(timeout_ms);
    if (deadline < 0)
        return -1;

    engine = &conn->tls.client.eng;

    for (;;)
    {
        unsigned st;
        int sendrec, recvrec;
        short events = 0;
        int revents;

        st = br_ssl_engine_current_state(engine);
        if (st == BR_SSL_CLOSED)
            return -1;

        sendrec = ((st & BR_SSL_SENDREC) != 0);
        recvrec = ((st & BR_SSL_RECVREC) != 0);

        if (!sendrec)
        {
            if (st & target)
                return 0;
            if (st & BR_SSL_RECVAPP)
            {
                errno = EPROTO;
                return -1;
            }
        }
        if (!sendrec && !recvrec)
        {
            br_ssl_engine_flush(engine, 0);
            continue;
        }

        if (sendrec)
            events |= POLLOUT;
        if (recvrec)
            events |= POLLIN;

        revents = wait_for_socket(conn->fd, events, deadline);
        if (revents < 0)
            return -1;

        if (sendrec && (revents & POLLOUT))
        {
            unsigned char *buf;
            size_t len;
            ssize_t wlen;

            buf = br_ssl_engine_sendrec_buf(engine, &len);
            wlen = send(conn->fd, buf, len, 0);
            if (wlen < 0)
            {
                int saved_errno = errno;

                if (saved_errno == EINTR || saved_errno == EAGAIN ||
                    saved_errno == EWOULDBLOCK)
                    continue;

                errno = saved_errno;
                return -1;
            }
            if (wlen == 0)
            {
                errno = EPIPE;
                return -1;
            }

            br_ssl_engine_sendrec_ack(engine, (size_t)wlen);
            continue;
        }

        if (recvrec && (revents & POLLIN))
        {
            unsigned char *buf;
            size_t len;
            ssize_t rlen;

            buf = br_ssl_engine_recvrec_buf(engine, &len);
            rlen = recv(conn->fd, buf, len, 0);
            if (rlen == 0)
            {
                errno = ECONNRESET;
                return -1;
            }
            if (rlen < 0)
            {
                int saved_errno = errno;

                if (saved_errno == EINTR || saved_errno == EAGAIN ||
                    saved_errno == EWOULDBLOCK)
                    continue;

                errno = saved_errno;
                return -1;
            }

            br_ssl_engine_recvrec_ack(engine, (size_t)rlen);
            continue;
        }

        errno = EIO;
        return -1;
    }
}

ssize_t tcp_read(conn_t *conn, void *buf, size_t len, int timeout_ms)
{
    int64_t deadline = deadline_after(timeout_ms);
    if (deadline < 0)
        return -1;

    for (;;)
    {
        ssize_t n = read(conn->fd, buf, len);

        if (n >= 0)
            return n;
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        if (wait_for_socket(conn->fd, POLLIN, deadline) < 0)
            return -1;
    }
}
ssize_t tcp_write(conn_t *conn, const void *buf, size_t len, int timeout_ms)
{
    int64_t deadline = deadline_after(timeout_ms);
    if (deadline < 0)
        return -1;

    for (;;)
    {
        ssize_t n = write(conn->fd, buf, len);

        if (n >= 0)
            return n;
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        if (wait_for_socket(conn->fd, POLLOUT, deadline) < 0)
            return -1;
    }
}
int tcp_close(conn_t *conn)
{
    return close(conn->fd);
}

ssize_t tls_read(conn_t *conn, void *dst_buf, size_t len, int timeout_ms)
{
    unsigned char *buf;
    size_t alen;

    if (len == 0)
    {
        return 0;
    }
    if (run_brssl_engine(conn, BR_SSL_RECVAPP, timeout_ms) < 0)
    {
        br_ssl_engine_context *engine = &conn->tls.client.eng;

        if (br_ssl_engine_current_state(engine) == BR_SSL_CLOSED &&
            br_ssl_engine_last_error(engine) == BR_ERR_OK)
            return 0;

        return -1;
    }
    buf = br_ssl_engine_recvapp_buf(&conn->tls.client.eng, &alen);
    if (alen > len)
    {
        alen = len;
    }
    memcpy(dst_buf, buf, alen);
    br_ssl_engine_recvapp_ack(&conn->tls.client.eng, alen);
    return alen;
}

ssize_t tls_write(conn_t *conn, const void *src_buf, size_t len,
                  int timeout_ms)
{
    unsigned char *buf;
    size_t alen;

    if (len == 0)
    {
        return 0;
    }
    if (run_brssl_engine(conn, BR_SSL_SENDAPP, timeout_ms) < 0)
    {
        return -1;
    }
    buf = br_ssl_engine_sendapp_buf(&conn->tls.client.eng, &alen);
    if (alen > len)
    {
        alen = len;
    }
    memcpy(buf, src_buf, alen);
    br_ssl_engine_sendapp_ack(&conn->tls.client.eng, alen);
    br_ssl_engine_flush(&conn->tls.client.eng, 0);
    return alen;
}
int tls_close(conn_t *conn)
{
    return close(conn->fd);
}

int parse_url(char *url, url_t *result)
{
    if (url == NULL || result == NULL || url[0] == '\0')
        return -1;

    char *f1;
    char *f2;
    strcpy(result->protocol, "https");
    strcpy(result->hostname, "");
    strcpy(result->port, "");
    strcpy(result->path, "/");

    char *sep1 = "://";
    char sep2 = '/';

    f1 = strstr(url, sep1);
    if (f1)
    {
        size_t proto_len = f1 - url;
        if (proto_len == 0 || proto_len >= PROTO_LENGTH)
            return -1;
        strncpy(result->protocol, url, proto_len);
        result->protocol[proto_len] = '\0';
        f1 += strlen(sep1);
    }

    char *host_start = f1 ? f1 : url;

    f2 = strchr(host_start, sep2);
    if (f2)
    {
        if (strlen(f2) >= PATH_LENGTH)
            return -1;
        strcpy(result->path, f2);
    }

    char *host_end = f2 ? f2 : host_start + strlen(host_start);
    char *port_start = memchr(host_start, ':', host_end - host_start);
    char *hostname_end = port_start ? port_start : host_end;
    size_t host_len = hostname_end - host_start;
    if (host_len == 0 || host_len >= HOST_LENGTH)
        return -1;

    strncpy(result->hostname, host_start, host_len);
    result->hostname[host_len] = '\0';

    if (port_start != NULL)
    {
        port_start++;
        size_t port_len = host_end - port_start;
        if (port_len == 0 || port_len >= PORT_LENGTH)
            return -1;
        for (size_t i = 0; i < port_len; i++)
            if (!isdigit((unsigned char)port_start[i]))
                return -1;
        strncpy(result->port, port_start, port_len);
        result->port[port_len] = '\0';
    }
    return 0;
}

ssize_t
read_exact(conn_t *conn, void *buf, size_t n)
{
    char *p = buf;
    size_t off = 0;
    while (off < n)
    {
        ssize_t rn = conn->read(conn, p + off, n - off, 10000);
        if (rn < 0)
            return -1;

        if (rn == 0)
        {
            errno = ECONNRESET;
            return -1;
        }

        off += rn;
    }
    return (ssize_t)off;
}

int fwrite_exact(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    size_t off = 0;
    size_t len = (size_t)n;
    do
    {
        ssize_t wn = write(fd, p + off, len - off);

        if (wn < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (wn == 0)
        {
            errno = EIO;
            return -1;
        }

        off += wn;

    } while (off < len);
    return 0;
}

int write_exact(conn_t *conn, const void *buf, size_t n)
{
    const char *p = buf;
    size_t off = 0;
    size_t len = (size_t)n;
    do
    {
        ssize_t wn = conn->write(conn, p + off, len - off, 10000);

        if (wn < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (wn == 0)
        {
            errno = EIO;
            return -1;
        }

        off += wn;

    } while (off < len);
    return 0;
}

int read_line(buf *buf, conn_t *conn)
{
    char c;
    ssize_t len;
    char *tmp;
    size_t tmpsize;

    if (buf->buffer == NULL)
    {
        if ((buf->buffer = malloc(512)) == NULL)
        {
            errno = ENOMEM;
            return (-1);
        }
        buf->capacity = 512;
    }

    buf->buffer[0] = '\0';
    buf->size = 0;

    do
    {
        len = read_exact(conn, &c, 1);
        if (len == -1)
            return (-1);

        buf->buffer[buf->size++] = c;

        if (buf->size == buf->capacity)
        {
            tmp = buf->buffer;
            tmpsize = buf->capacity * 2 + 1;
            if ((tmp = realloc(tmp, tmpsize)) == NULL)
            {
                errno = ENOMEM;
                return (-1);
            }
            buf->buffer = tmp;
            buf->capacity = tmpsize;
        }

    } while (c != '\n');

    buf->buffer[buf->size] = '\0';

    return (0);
}

int parse_status_line(char *line, int *status)
{
    char *version, *code, *sp;
    int st;

    if (line == NULL || status == NULL)
        return -1;

    line[strcspn(line, "\r\n")] = '\0';

    version = line;

    sp = strchr(line, ' ');
    if (sp == NULL)
        return -1;

    *sp++ = '\0';

    if (*sp == ' ' || *sp == '\0')
        return -1;

    code = sp;

    sp = strchr(code, ' ');
    if (sp != NULL)
        *sp = '\0';

    /* Accept HTTP/1.x only. */
    if (strlen(version) != 8 ||
        strncmp(version, "HTTP/1.", 7) != 0 ||
        !isdigit((unsigned char)version[7]))
        return -1;

    if (strlen(code) != 3 ||
        !isdigit((unsigned char)code[0]) ||
        !isdigit((unsigned char)code[1]) ||
        !isdigit((unsigned char)code[2]))
        return -1;

    st = (code[0] - '0') * 100 +
         (code[1] - '0') * 10 +
         (code[2] - '0');

    *status = st;

    return 0;
}

int connect_url(url_t p_url, conn_t *conn)
{
    const char *service;
    struct addrinfo *dns_res, *dns_res0 = NULL;
    conn->fd = -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    service = p_url.port[0] != '\0' ? p_url.port : p_url.protocol;

    int e;
    if ((e = getaddrinfo(p_url.hostname, service, &hints, &dns_res0)) != 0)
    {
        return http_fail(HTTP_ERR_CONNECT, gai_strerror(e));
    }

    for (dns_res = dns_res0; dns_res; dns_res = dns_res->ai_next)
    {

        conn->fd = socket(dns_res->ai_family,
                          dns_res->ai_socktype,
                          dns_res->ai_protocol);

        if (conn->fd < 0)
        {
            continue;
        }
        int e;
        while ((e = connect(conn->fd, dns_res->ai_addr, dns_res->ai_addrlen)) < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        if (e < 0)
        {
            close(conn->fd);
            conn->fd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(dns_res0);

    if (conn->fd < 0)
        return http_fail(HTTP_ERR_CONNECT, "cannot connect");

    int flags = fcntl(conn->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        close(conn->fd);
        conn->fd = -1;
        return http_fail(HTTP_ERR_CONNECT, "setting nonblocking mode");
    }

    if (strcasecmp(p_url.protocol, "https") == 0)
    {
        br_ssl_client_init_full(
            &conn->tls.client,
            &conn->tls.x509,
            TAs,
            TAs_NUM);
        br_ssl_engine_set_buffer(&conn->tls.client.eng, &conn->tls.iobuf, sizeof conn->tls.iobuf, 1);

        if (!br_ssl_client_reset(&conn->tls.client,
                                 p_url.hostname, 0))
        {
            return http_fail(HTTP_ERR_CONNECT, "initializing TLS");
        }

        conn->read = tls_read;
        conn->write = tls_write;
        conn->close = tls_close;
    }
    else
    {
        conn->read = tcp_read;
        conn->write = tcp_write;
        conn->close = tcp_close;
    }

    return HTTP_OK;
}

int read_status(conn_t *conn, int *status, buf *line)
{
    int info_responses = 0;

    while (1)
    {
        if (read_line(line, conn) == -1)
        {
            return http_fail(HTTP_ERR_IO, "reading status line");
        }

        if (parse_status_line(line->buffer, status) == -1)
        {
            return http_fail(HTTP_ERR_STATUS_INVALID_LINE, NULL);
        }

        if (*status == 101)
        {
            return http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, "101 Switching Protocols");
        }

        if (*status >= 100 && *status < 200)
        {
            if (++info_responses > MAX_INFO_RESPONSES)
                return http_fail(HTTP_ERR_IO, "max info headers reached");

            // discard headers
            while (1)
            {
                if (read_line(line, conn) == -1)
                    return http_fail(HTTP_ERR_IO, "reading interim response header");

                if (strcmp(line->buffer, "\r\n") == 0 ||
                    strcmp(line->buffer, "\n") == 0)
                    break;
            }
            continue;
        }

        return HTTP_OK;
    }
}

int read_headers(conn_t *conn, buf *line, http_headers_t *headers)
{

    headers->content_length = -1;
    headers->chunked = 0;
    headers->has_location = 0;
    headers->location[0] = '\0';

    char *col = NULL;
    char *h_key = NULL;
    char *h_val = NULL;

    while (1)
    {
        if (read_line(line, conn) == -1)
        {
            return http_fail(HTTP_ERR_IO, "reading header");
        }

        if (strcmp(line->buffer, "\r\n") == 0)
            break;

        col = strchr(line->buffer, ':');

        if (col == NULL)
        {
            return http_fail(HTTP_ERR_HEADER_MALFORMED, line->buffer);
        }

        *col = '\0';

        h_key = line->buffer;
        h_val = col + 1;

        while (*h_val == ' ' || *h_val == '\t')
            h_val++;

        h_val[strcspn(h_val, "\r\n")] = '\0';

        // printf("key:%s value:%s\n", h_key, h_val);

        if (strcasecmp(h_key, "Content-Encoding") == 0 &&
            strcasecmp(h_val, "identity") != 0)
        {
            return http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, "unsupported Content-Encoding");
        }

        if (strcasecmp(h_key, "Content-Length") == 0)
        {
            char *end;
            long val;
            errno = 0;
            val = strtol(h_val, &end, 10);
            if (end == h_val || *end != '\0' || errno == ERANGE || val < 0 || (headers->content_length >= 0 && val != headers->content_length))
            {
                return http_fail(HTTP_ERR_HEADER_INVALID_CONTENT_LENGTH, h_val);
            }
            headers->content_length = val;
        }
        if (strcasecmp(h_key, "Transfer-Encoding") == 0)
        {
            if (strcasecmp(h_val, "Chunked") == 0)
            {
                headers->chunked = 1;
                continue;
            }
            return http_fail(HTTP_ERR_HEADER_UNSUPPORTED_TRANSFER_ENCODING,
                             h_val);
        }
        if (strcasecmp(h_key, "Location") == 0)
        {
            headers->has_location = 1;
            if (strlen(h_val) + 1 > URL_LENGTH)
            {
                return http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, "unsupported location size");
            }
            strcpy(headers->location, h_val);
        }
    };
    return HTTP_OK;
}

int read_body(conn_t *conn, int dfile, buf *line,
              const http_headers_t *headers, const http_req_t *req)
{
    ssize_t rn = 0;
    char res_buf[2048];

    if (headers->chunked)
    {
        size_t down_n = 0;
        while (1)
        {
            if (read_line(line, conn) == -1)
            {
                return http_fail(HTTP_ERR_BODY_TRUNCATED, NULL);
            };

            size_t chunk_size = 0;
            char *p;

            if (line->size < 2 || !isxdigit((unsigned char)*line->buffer))
                return http_fail(HTTP_ERR_BODY_INVALID_CHUNK_SIZE, NULL);

            for (p = line->buffer; *p && !isspace((unsigned char)*p); ++p)
            {
                int digit;

                if (*p == ';')
                    break;
                if (!isxdigit((unsigned char)*p))
                    return http_fail(HTTP_ERR_BODY_INVALID_CHUNK_SIZE, NULL);
                if (isdigit((unsigned char)*p))
                {
                    digit = *p - '0';
                }
                else
                {
                    digit = 10 + tolower((unsigned char)*p) - 'a';
                }
                if (chunk_size > (SIZE_MAX - (size_t)digit) / 16)
                    return http_fail(HTTP_ERR_BODY_INVALID_CHUNK_SIZE, NULL);
                chunk_size = chunk_size * 16 + (size_t)digit;
            }

            if (chunk_size == 0)
            {
                if (read_line(line, conn) == -1)
                    return http_fail(HTTP_ERR_BODY_TRUNCATED, NULL);
                break;
            }

            // printf("bytes: %d\n", val);

            size_t total = chunk_size;
            while (total)
            {
                size_t want = total < sizeof(res_buf) ? total : sizeof(res_buf);
                rn = read_exact(conn, res_buf, want);
                if (rn < 0)
                {
                    if (errno == ECONNRESET)
                        return http_fail(HTTP_ERR_BODY_TRUNCATED, NULL);
                    return http_fail(HTTP_ERR_IO, "reading chunk body");
                }

                if (fwrite_exact(dfile, res_buf, rn) == -1)
                    return http_fail(HTTP_ERR_IO, "writing file");

                down_n += rn;
                total -= rn;
                if (req->on_progress)
                    req->on_progress(down_n, 0);
            }

            rn = read_exact(conn, res_buf, 2);
            if (rn < 0)
            {
                if (errno == ECONNRESET)
                    return http_fail(HTTP_ERR_BODY_TRUNCATED, NULL);
                return http_fail(HTTP_ERR_IO, "reading chunk terminator");
            }
            if (res_buf[0] != '\r' || res_buf[1] != '\n')
                return http_fail(HTTP_ERR_BODY_INVALID_CHUNK_SIZE, NULL);
        }
    }
    else if (headers->content_length >= 0)
    {
        size_t total = headers->content_length;
        while (total)
        {
            size_t want = total < sizeof(res_buf) ? total : sizeof(res_buf);
            rn = read_exact(conn, res_buf, want);
            if (rn < 0)
            {
                if (errno == ECONNRESET)
                    return http_fail(HTTP_ERR_BODY_TRUNCATED, NULL);
                return http_fail(HTTP_ERR_IO, "reading body");
            }

            if (fwrite_exact(dfile, res_buf, rn) == -1)
                return http_fail(HTTP_ERR_IO, "writing file");
            total -= rn;
            if (req->on_progress)
                req->on_progress(headers->content_length - total, headers->content_length);
        }
    }
    else
    {
        size_t down_n = 0;
        while ((rn = conn->read(conn, res_buf, sizeof(res_buf), 10000)) > 0)
        {
            if (fwrite_exact(dfile, res_buf, rn) == -1)
                return http_fail(HTTP_ERR_IO, "writing file");
            down_n += rn;
            if (req->on_progress)
                req->on_progress(down_n, 0);
        }

        if (rn < 0)
            return http_fail(HTTP_ERR_IO, "reading body");
    }
    return HTTP_OK;
}

int http_get(http_req_t req)
{

    conn_t conn = (conn_t){0};
    int result;
    int no_body;

    char req_buf[6114];
    buf line = {.buffer = NULL, .capacity = 0, .size = 0};

    int dfile = -1;
    http_headers_t headers;

    char c_url[URL_LENGTH];
    int url_n = snprintf(c_url, sizeof(c_url), "%s", req.url);
    if (url_n < 0 || (size_t)url_n >= sizeof(c_url))
        return http_fail(HTTP_ERR_URL_INVALID, req.url);

    url_t p_url;

    int redirects = 0;
    int redirect = 0;

    do
    {

        redirect = 0;

        conn.fd = -1;
        ssize_t n = 0;
        no_body = 0;
        int status;
        result = HTTP_OK;
        p_url = (url_t){0};
        char authority[HOST_LENGTH + 7];

        if (parse_url(c_url, &p_url) == -1)
        {
            result = http_fail(HTTP_ERR_URL_INVALID, req.url);
            goto cleanup;
        }

        result = connect_url(p_url, &conn);
        if (result != HTTP_OK)
            goto cleanup;

        if (p_url.port[0] != '\0')
            n = snprintf(authority, sizeof(authority), "%s:%s",
                         p_url.hostname, p_url.port);
        else
            n = snprintf(authority, sizeof(authority), "%s", p_url.hostname);
        if (n < 0 || (size_t)n >= sizeof(authority))
        {
            result = http_fail(HTTP_ERR_URL_INVALID, req.url);
            goto cleanup;
        }

        n = snprintf(req_buf, sizeof(req_buf), "GET %s HTTP/1.1\r\n"
                                               "Host: %s\r\n"
                                               "User-Agent: aryan-http-client/0.1\r\n"
                                               "Accept: */*\r\n"
                                               "Accept-Encoding: identity\r\n"
                                               "Connection: close\r\n"
                                               "\r\n",
                     p_url.path, authority);
        if (n < 0 || (size_t)n >= sizeof(req_buf))
        {
            result = http_fail(HTTP_ERR_REQUEST_TOO_LARGE, NULL);
            goto cleanup;
        }

        if (write_exact(&conn, req_buf, n) == -1)
        {
            result = http_fail(HTTP_ERR_IO, "sending request");
            goto cleanup;
        }

        result = read_status(&conn, &status, &line);
        if (result != HTTP_OK)
            goto cleanup;

        // printf("%s", line.buffer);

        // printf("status:%d\n\n", status);

        switch (status)
        {
        case 200:
            break;

        case 204:
            no_body = 1;
            break;

        case 301:
        case 302:
        case 303:
        case 307:
        case 308:
            redirect = 1;
            break;

        case 206:
            result = http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED,
                               "206 Partial Content without Range support");
            goto cleanup;

        case 401:
            result = http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED,
                               "401 Authorization Required");
            goto cleanup;

        case 407:
            result = http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED,
                               "407 Proxy Authentication Required");
            goto cleanup;

        default:
            if (status >= 500 && status <= 599)
            {
                result = http_fail(HTTP_ERR_RESPONSE_SERVER_ERROR, NULL);
                goto cleanup;
            }

            if (status >= 400 && status <= 499)
            {
                result = http_fail(HTTP_ERR_RESPONSE_CLIENT_ERROR, NULL);
                goto cleanup;
            }

            result = http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, NULL);
            goto cleanup;
        }

        // read headers

        result = read_headers(&conn, &line, &headers);
        if (result != HTTP_OK)
            goto cleanup;

        if (redirect)
        {
            if (!headers.has_location)
            {
                result = http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, "redirect without Location");
                goto cleanup;
            }

            if (headers.location[0] == '/')
            {
                if (p_url.port[0] != '\0')
                    url_n = snprintf(c_url, sizeof(c_url), "%s://%s:%s%s",
                                     p_url.protocol, p_url.hostname,
                                     p_url.port, headers.location);
                else
                    url_n = snprintf(c_url, sizeof(c_url), "%s://%s%s",
                                     p_url.protocol, p_url.hostname,
                                     headers.location);
            }
            else
                url_n = snprintf(c_url, sizeof(c_url), "%s", headers.location);
            if (url_n < 0 || (size_t)url_n >= sizeof(c_url))
            {
                result = http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, "unsupported location size");
                goto cleanup;
            }

            conn.close(&conn);
        }
    } while (redirect && ++redirects <= MAX_REDIRECTS);

    if (redirect)
    {
        result = http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, "too many redirects");
        goto cleanup;
    }

    if (no_body)
    {
        goto cleanup;
    }

    char *filename = !strcmp(p_url.path, "/") ? "unknown" : strrchr(p_url.path, '/') + 1;
    dfile = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (dfile == -1)
    {
        result = http_fail(HTTP_ERR_IO, filename);
        goto cleanup;
    }

    printf("\n");
    // read body
    result = read_body(&conn, dfile, &line, &headers, &req);
    if (result != HTTP_OK)
        goto cleanup;

cleanup:
    if (line.buffer)
        free(line.buffer);
    if (conn.close)
        conn.close(&conn);
    if (dfile >= 0)
        close(dfile);

    return result;
}

void on_progress(size_t received, size_t total)
{
    if (total)
        printf("\r%zu/%zu", received, total);
    else
        printf("\r%zu", received);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    const char *url = NULL;

    if (argc == 2)
        url = argv[1];
    else
        return http_fail(HTTP_ERR_USAGE, "usage: http_client URL");

    http_req_t req = {.url = url,
                      .on_progress = on_progress,
                      .sink = NULL};
    return http_get(req);
}
