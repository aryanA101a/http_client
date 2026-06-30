#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <err.h>
#include <errno.h>
#include <time.h>

#include "bearssl.h"
#include "http_client.h"
#include "trust_anchors.inc"

#define PROTO_LENGTH 6
#define HOST_LENGTH 254
#define PORT_LENGTH 6
#define PATH_LENGTH 4096

#define URL_LENGTH (PROTO_LENGTH + 3 + HOST_LENGTH + 1 + PORT_LENGTH + PATH_LENGTH)

#define MAX_REDIRECTS 5
#define MAX_INFO_RESPONSES 10
#define IO_TIMEOUT_MS 10000

// should be initialized by {null,0,0} if not allocated at the initialization
struct line_buffer
{
    char *buffer;
    size_t capacity;
    size_t size;
};

struct url
{
    char protocol[PROTO_LENGTH];
    char hostname[HOST_LENGTH];
    char port[PORT_LENGTH];
    char path[PATH_LENGTH];
};

struct tls_ctx
{
    br_ssl_client_context client;
    br_x509_minimal_context x509;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
};

struct conn
{
    int fd;
    struct tls_ctx tls;

    ssize_t (*read)(struct conn *conn, void *buf, size_t len,
                    int64_t deadline);
    ssize_t (*write)(struct conn *conn, const void *buf, size_t len,
                     int64_t deadline);
    int (*close)(struct conn *conn);
};

struct http_headers
{
    ssize_t content_length;
    int chunked;
    int has_location;
    char location[URL_LENGTH];
};

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

static int
http_fail(http_error_t err, const char *detail)
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
check_deadline(int64_t deadline)
{
    int64_t cur_ms;

    if (deadline < 0)
    {
        errno = EINVAL;
        return -1;
    }

    cur_ms = now_ms();
    if (cur_ms < 0)
        return -1;
    if (cur_ms >= deadline)
    {
        errno = ETIMEDOUT;
        return -1;
    }

    return 0;
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
run_brssl_engine(struct conn *conn, unsigned int target, int64_t deadline)
{
    br_ssl_engine_context *engine;

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
    if (deadline < 0)
    {
        errno = EINVAL;
        return -1;
    }

    engine = &conn->tls.client.eng;

    for (;;)
    {
        unsigned st;
        int sendrec, recvrec;
        short events = 0;
        int revents;

        if (check_deadline(deadline) < 0)
            return -1;

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

ssize_t tcp_read(struct conn *conn, void *buf, size_t len, int64_t deadline)
{
    for (;;)
    {
        ssize_t n;

        if (check_deadline(deadline) < 0)
            return -1;

        n = read(conn->fd, buf, len);
        if (n >= 0)
            return n;
        if (errno == EINTR)
        {
            if (check_deadline(deadline) < 0)
                return -1;
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        if (wait_for_socket(conn->fd, POLLIN, deadline) < 0)
            return -1;
    }
}
ssize_t tcp_write(struct conn *conn, const void *buf, size_t len,
                  int64_t deadline)
{
    for (;;)
    {
        ssize_t n;

        if (check_deadline(deadline) < 0)
            return -1;

        n = write(conn->fd, buf, len);
        if (n >= 0)
            return n;
        if (errno == EINTR)
        {
            if (check_deadline(deadline) < 0)
                return -1;
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        if (wait_for_socket(conn->fd, POLLOUT, deadline) < 0)
            return -1;
    }
}
int tcp_close(struct conn *conn)
{
    return close(conn->fd);
}

ssize_t tls_read(struct conn *conn, void *dst_buf, size_t len, int64_t deadline)
{
    unsigned char *buf;
    size_t alen;

    if (len == 0)
    {
        return 0;
    }
    if (check_deadline(deadline) < 0)
        return -1;
    if (run_brssl_engine(conn, BR_SSL_RECVAPP, deadline) < 0)
    {
        br_ssl_engine_context *engine = &conn->tls.client.eng;

        if (br_ssl_engine_current_state(engine) == BR_SSL_CLOSED &&
            br_ssl_engine_last_error(engine) == BR_ERR_OK)
            return 0;

        return -1;
    }
    if (check_deadline(deadline) < 0)
        return -1;
    buf = br_ssl_engine_recvapp_buf(&conn->tls.client.eng, &alen);
    if (alen > len)
    {
        alen = len;
    }
    memcpy(dst_buf, buf, alen);
    br_ssl_engine_recvapp_ack(&conn->tls.client.eng, alen);
    return alen;
}

ssize_t tls_write(struct conn *conn, const void *src_buf, size_t len,
                  int64_t deadline)
{
    unsigned char *buf;
    size_t alen;

    if (len == 0)
    {
        return 0;
    }
    if (check_deadline(deadline) < 0)
        return -1;
    if (run_brssl_engine(conn, BR_SSL_SENDAPP, deadline) < 0)
    {
        return -1;
    }
    if (check_deadline(deadline) < 0)
        return -1;
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
int tls_close(struct conn *conn)
{
    return close(conn->fd);
}

void conn_close(struct conn *conn)
{
    if (conn->fd >= 0)
    {
        if (conn->close)
            conn->close(conn);
        else
            close(conn->fd);
    }

    conn->fd = -1;
    conn->read = NULL;
    conn->write = NULL;
    conn->close = NULL;
}

int parse_url(char *url, struct url *result)
{
    if (url == NULL || result == NULL || url[0] == '\0')
        return -1;

    char *scheme_end;
    char *host_start;
    char *path_start;
    const char *scheme_delim = "://";

    strcpy(result->protocol, "https");
    strcpy(result->hostname, "");
    strcpy(result->port, "");
    strcpy(result->path, "/");

    host_start = url;
    scheme_end = strstr(url, scheme_delim);
    if (scheme_end)
    {
        size_t proto_len = scheme_end - url;
        if (proto_len == 0 || proto_len >= PROTO_LENGTH)
            return -1;
        memcpy(result->protocol, url, proto_len);
        result->protocol[proto_len] = '\0';
        host_start = scheme_end + strlen(scheme_delim);
    }
    if (strcasecmp(result->protocol, "http") != 0 &&
        strcasecmp(result->protocol, "https") != 0)
        return -1;

    path_start = strchr(host_start, '/');
    if (path_start)
    {
        if (strlen(path_start) >= PATH_LENGTH)
            return -1;
        strcpy(result->path, path_start);
    }

    char *host_end = path_start ? path_start : host_start + strlen(host_start);
    char *port_start = memchr(host_start, ':', host_end - host_start);
    char *hostname_end = port_start ? port_start : host_end;
    size_t host_len = hostname_end - host_start;
    if (host_len == 0 || host_len >= HOST_LENGTH)
        return -1;

    memcpy(result->hostname, host_start, host_len);
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
        memcpy(result->port, port_start, port_len);
        result->port[port_len] = '\0';
    }
    return 0;
}

ssize_t
read_exact(struct conn *conn, void *buf, size_t n)
{
    char *p = buf;
    int64_t deadline;
    size_t off = 0;

    deadline = deadline_after(IO_TIMEOUT_MS);
    if (deadline < 0)
        return -1;

    while (off < n)
    {
        ssize_t rn = conn->read(conn, p + off, n - off, deadline);
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

int write_exact(struct conn *conn, const void *buf, size_t n)
{
    const char *p = buf;
    int64_t deadline;
    size_t off = 0;
    size_t len = (size_t)n;

    deadline = deadline_after(IO_TIMEOUT_MS);
    if (deadline < 0)
        return -1;

    while (off < len)
    {
        ssize_t wn;

        wn = conn->write(conn, p + off, len - off, deadline);

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
    }
    return 0;
}

int read_line(struct conn *conn, struct line_buffer *line)
{
    char c;
    int64_t deadline;
    ssize_t len;
    char *tmp;
    size_t tmpsize;

    if (line->buffer == NULL)
    {
        if ((line->buffer = malloc(512)) == NULL)
        {
            errno = ENOMEM;
            return (-1);
        }
        line->capacity = 512;
    }

    line->buffer[0] = '\0';
    line->size = 0;
    deadline = deadline_after(IO_TIMEOUT_MS);
    if (deadline < 0)
        return (-1);

    do
    {
        len = conn->read(conn, &c, 1, deadline);
        if (len == -1)
            return (-1);
        if (len == 0)
        {
            errno = ECONNRESET;
            return (-1);
        }

        line->buffer[line->size++] = c;

        if (line->size == line->capacity)
        {
            tmp = line->buffer;
            tmpsize = line->capacity * 2 + 1;
            if ((tmp = realloc(tmp, tmpsize)) == NULL)
            {
                errno = ENOMEM;
                return (-1);
            }
            line->buffer = tmp;
            line->capacity = tmpsize;
        }

    } while (c != '\n');

    line->buffer[line->size] = '\0';

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

const char *output_name_from_path(const char *path)
{
    const char *slash;

    slash = strrchr(path, '/');
    if (slash == NULL || slash[1] == '\0')
        return "unknown";

    return slash + 1;
}

int connect_url(struct conn *conn, const struct url *url)
{
    const char *service;
    struct addrinfo *dns_res, *dns_res0 = NULL;
    conn->fd = -1;
    conn->read = NULL;
    conn->write = NULL;
    conn->close = NULL;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    service = url->port[0] != '\0' ? url->port : url->protocol;

    int e;
    if ((e = getaddrinfo(url->hostname, service, &hints, &dns_res0)) != 0)
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
            conn_close(conn);
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
        conn_close(conn);
        return http_fail(HTTP_ERR_CONNECT, "setting nonblocking mode");
    }

    if (strcasecmp(url->protocol, "https") == 0)
    {
        br_ssl_client_init_full(
            &conn->tls.client,
            &conn->tls.x509,
            TAs,
            TAs_NUM);
        br_ssl_engine_set_buffer(&conn->tls.client.eng, &conn->tls.iobuf, sizeof conn->tls.iobuf, 1);

        if (!br_ssl_client_reset(&conn->tls.client,
                                 url->hostname, 0))
        {
            conn_close(conn);
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

int read_status(struct conn *conn, int *status, struct line_buffer *line)
{
    int info_responses = 0;

    while (1)
    {
        if (read_line(conn, line) == -1)
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
                if (read_line(conn, line) == -1)
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

int read_headers(struct conn *conn, struct http_headers *headers,
                 struct line_buffer *line)
{

    headers->content_length = -1;
    headers->chunked = 0;
    headers->has_location = 0;
    headers->location[0] = '\0';

    char *col = NULL;
    char *header_name = NULL;
    char *header_value = NULL;

    while (1)
    {
        if (read_line(conn, line) == -1)
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

        header_name = line->buffer;
        header_value = col + 1;

        while (*header_value == ' ' || *header_value == '\t')
            header_value++;

        header_value[strcspn(header_value, "\r\n")] = '\0';

        // printf("key:%s value:%s\n", header_name, header_value);

        if (strcasecmp(header_name, "Content-Encoding") == 0 &&
            strcasecmp(header_value, "identity") != 0)
        {
            return http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, "unsupported Content-Encoding");
        }

        if (strcasecmp(header_name, "Content-Length") == 0)
        {
            char *end;
            long val;
            errno = 0;
            val = strtol(header_value, &end, 10);
            if (end == header_value || *end != '\0' || errno == ERANGE || val < 0 || (headers->content_length >= 0 && val != headers->content_length))
            {
                return http_fail(HTTP_ERR_HEADER_INVALID_CONTENT_LENGTH,
                                 header_value);
            }
            headers->content_length = val;
        }
        if (strcasecmp(header_name, "Transfer-Encoding") == 0)
        {
            if (strcasecmp(header_value, "Chunked") == 0)
            {
                headers->chunked = 1;
                continue;
            }
            return http_fail(HTTP_ERR_HEADER_UNSUPPORTED_TRANSFER_ENCODING,
                             header_value);
        }
        if (strcasecmp(header_name, "Location") == 0)
        {
            headers->has_location = 1;
            if (strlen(header_value) + 1 > URL_LENGTH)
            {
                return http_fail(HTTP_ERR_RESPONSE_UNSUPPORTED, "unsupported location size");
            }
            strcpy(headers->location, header_value);
        }
    };
    return HTTP_OK;
}

int read_body(struct conn *conn, sink_t *sink, const struct http_headers *headers,
              const http_req_t *req, struct line_buffer *line)
{
    ssize_t rn = 0;
    char res_buf[2048];

    if (headers->chunked)
    {
        size_t down_n = 0;
        while (1)
        {
            if (read_line(conn, line) == -1)
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
                if (read_line(conn, line) == -1)
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

                if (sink->write(sink, res_buf, rn) == -1)
                    return http_fail(HTTP_ERR_IO, "writing output");

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

            if (sink->write(sink, res_buf, rn) == -1)
                return http_fail(HTTP_ERR_IO, "writing output");
            total -= rn;
            if (req->on_progress)
                req->on_progress(headers->content_length - total, headers->content_length);
        }
    }
    else
    {
        size_t down_n = 0;
        for (;;)
        {
            int64_t deadline = deadline_after(IO_TIMEOUT_MS);

            if (deadline < 0)
                return http_fail(HTTP_ERR_IO, "reading body");
            rn = conn->read(conn, res_buf, sizeof(res_buf), deadline);
            if (rn <= 0)
                break;

            if (sink->write(sink, res_buf, rn) == -1)
                return http_fail(HTTP_ERR_IO, "writing output");
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

    struct conn conn = {.fd = -1};
    int result;
    int no_body;

    char req_buf[6114];
    struct line_buffer line = {.buffer = NULL, .capacity = 0, .size = 0};

    sink_t *sink = req.sink;
    int sink_open = 0;
    struct http_headers headers;

    if (sink == NULL)
        return http_fail(HTTP_ERR_USAGE, "sink required");

    char c_url[URL_LENGTH];
    int url_n = snprintf(c_url, sizeof(c_url), "%s", req.url);
    if (url_n < 0 || (size_t)url_n >= sizeof(c_url))
        return http_fail(HTTP_ERR_URL_INVALID, req.url);

    struct url p_url;

    int redirects = 0;
    int redirect = 0;

    do
    {

        redirect = 0;

        ssize_t n = 0;
        no_body = 0;
        int status;
        result = HTTP_OK;
        p_url = (struct url){0};
        char authority[HOST_LENGTH + 7];

        if (parse_url(c_url, &p_url) == -1)
        {
            result = http_fail(HTTP_ERR_URL_INVALID, req.url);
            goto cleanup;
        }

        result = connect_url(&conn, &p_url);
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

        result = read_headers(&conn, &headers, &line);
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

            conn_close(&conn);
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

    result = sink->open(sink, output_name_from_path(p_url.path));
    if (result != HTTP_OK)
        goto cleanup;
    sink_open = 1;

    result = read_body(&conn, sink, &headers, &req, &line);
    if (result != HTTP_OK)
        goto cleanup;

cleanup:
    if (sink_open)
        sink->close(sink);
    if (line.buffer)
        free(line.buffer);
    conn_close(&conn);

    return result;
}
