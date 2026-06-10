#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <err.h>
#include <errno.h>
#include <time.h>

typedef struct url
{
    char protocol[6];
    char hostname[254];
    char path[4096];
} url_t;

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

void parse_url(char *url, url_t *result)
{
    int pn = 0;
    int prn = 0;
    strcpy(result->protocol, "https");
    strcpy(result->hostname, "");
    strcpy(result->path, "/");

    char *sep1 = "://";
    char sep2 = '/';

    int start = 0;
    int sep1_cur = 0;
    for (int cur = 0; cur <= strlen(url); cur++)
    {
        if (sep1_cur == strlen(sep1) - 1)
        {

            prn = snprintf(result->protocol, cur - 1, "%.*s\n", cur - 1, url);
            start = cur + 1;
            sep1_cur = -1;
            continue;
        }
        if (url[cur] == sep1[sep1_cur])
        {
            sep1_cur++;
            continue;
        }

        if (url[cur] == sep2 && !(url[cur - 1] == ':' || url[cur - 1] == '/'))
        {
            pn = snprintf(result->path, strlen(url) - cur + 1, "%.*s\n", strlen(url) - cur + 1, url + cur);
            snprintf(result->hostname, strlen(url) - prn - pn + 1, "%.*s\n", strlen(url) - prn - pn + 1, url + prn + 1);
            break;
        }

        if (cur == strlen(url) - 1)
        {
            char *s = !prn ? url + prn + 1 : url;
            int l = !prn ? strlen(url) - prn : strlen(url);
            snprintf(result->hostname, l, "%.*s\n", l, s);
        }
        start++;
    }
}

void print_line(char *buf, size_t n)
{
    for (ssize_t i = 0; i < n; i++)
    {
        unsigned char c = buf[i];

        if (c == '\r')
            printf("\\r");
        else if (c == '\n')
            printf("\\n\n");
        else if (c == '\t')
            printf("\\t");
        else if (isprint(c))
            putchar(c);
        else
            printf("\\x%02x", c);
    }
}

int64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;

    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

ssize_t read_exact(int fd, void *buf, size_t n)
{
    int64_t start_ms = now_ms();

    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int ret;

    while (1)
    {
        ret = poll(&pfd, 1, 250);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (ret == 0)
        {
            if (now_ms() - start_ms > 10000)
            {
                puts("idle timeout");
                return -1;
            }
            continue;
        }

        if (pfd.revents & POLLIN)
        {
            ssize_t rn = read(fd, buf, n);
            if (rn < 0 && errno == EINTR)
                continue;

            return rn;
        }
        if (pfd.revents & (POLLERR | POLLNVAL | POLLHUP))
        {
            errno = EIO;
            return -1;
        }
    }
}

// should be initialized by {null,0,0} if not allocated at the initialization
typedef struct
{
    char *buffer;
    size_t capacity;
    size_t size;
} buf;

int read_line(buf *buf, int fd)
{
    char c;
    size_t len;
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
        len = read_exact(fd, &c, 1);
        if (len == -1)
            return (-1);
        if (len == 0)
            break;

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

int http_get(http_req_t req)
{
    url_t p_url;
    struct addrinfo *dns_res, *dns_res0;
    char req_buf[6114];
    char res_buf[2048];
    int n = 0;
    ssize_t rn = 0;
    int e;
    ssize_t c_len = -1;
    int chunked = 0;
    FILE *sfp = NULL;
    FILE *dfile = NULL;
    char version[16];
    int status;
    buf line = {.buffer = NULL, .capacity = 0, .size = 0};

    parse_url(req.url, &p_url);

    char *filename = !strcmp(p_url.path, "/") ? "unknown" : strrchr(p_url.path, '/') + 1;
    dfile = fopen(filename, "wb");

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    e = getaddrinfo(p_url.hostname, p_url.protocol, &hints, &dns_res0);
    if (e != 0)
    {
        printf("%s\n", gai_strerror(e));
        goto cleanup;
    }

    int s = -1;
    for (dns_res = dns_res0; dns_res; dns_res = dns_res->ai_next)
    {

        s = socket(dns_res->ai_family,
                   dns_res->ai_socktype,
                   dns_res->ai_protocol);

        if (s < 0)
        {
            perror("socket");
            continue;
        }

        if (connect(s, dns_res->ai_addr, dns_res->ai_addrlen) < 0)
        {
            perror("connect");
            close(s);
            s = -1;
            continue;
        }

        printf("connected!\n\n");
        break;
    }

    if (s < 0)
    {
        err(1, "%s", "cannot connect");
        goto cleanup;
    }
    freeaddrinfo(dns_res0);

    n = snprintf(req_buf, sizeof(req_buf), "GET %s HTTP/1.1\r\n"
                                           "Host: %s\r\n"
                                           "User-Agent: aryan-http-client/0.1\r\n"
                                           "Accept: */*\r\n"
                                           "\r\n",
                 p_url.path, p_url.hostname);
    write(s, req_buf, n);

    // sfp = fdopen(s, "r+");
    // if (!sfp)
    // {
    //     perror("fdopen");
    //     goto cleanup;
    // }

    if (read_line(&line, s) == -1)
    {
        goto cleanup;
    }

    // printf("%s", line.buffer);
    if (sscanf(line.buffer, "%15s %d", version, &status) != 2)
    {
        puts("bad status");
        goto cleanup;
    }

    printf("version:%s status:%d\n\n", version, status);

    char *col = NULL;
    char *h_key = NULL;
    char *h_val = NULL;
    do
    {
        if (read_line(&line, s) == -1)
        {
            goto cleanup;
        }

        col = strchr(line.buffer, ':');

        if (col)
        {
            *col = '\0';

            h_key = line.buffer;
            h_val = col + 1;

            while (*h_val == ' ' || *h_val == '\t')
                h_val++;

            h_val[strcspn(h_val, "\r\n")] = '\0';

            printf("key:%s value:%s\n", h_key, h_val);

            if (strcasecmp(h_key, "Content-Length") == 0)
            {
                char *end;
                long val;
                val = strtol(h_val, &end, 10);
                if (end == h_val)
                {
                    puts("invalid value");
                }
                c_len = val;
            }
            if (strcasecmp(h_key, "Transfer-Encoding") == 0 && strcasecmp(h_val, "Chunked") == 0)
            {
                chunked = 1;
            }
        }

    } while (strcmp(line.buffer, "\r\n") != 0);

    printf("\n");
    if (c_len >= 0)
    {
        puts("content_length");
        size_t total = c_len;
        while (total)
        {
            size_t want = total < sizeof(res_buf) ? total : sizeof(res_buf);
            rn = read_exact(s, res_buf, want);
            if (rn == 0)
            {
                puts("response truncated");
                goto cleanup;
            }
            if (rn < 0)
            {
                perror("read");
                goto cleanup;
            }

            fwrite(res_buf, 1, rn, dfile);
            total -= rn;
            req.on_progress(c_len - total, c_len);
        }
    }
    else if (chunked)
    {
        puts("chunked");

        size_t down_n = 0;
        while (1)
        {
            size_t ch_len = -1;
            if (read_line(&line, s) == -1)
            {
                puts("request truncated");
                goto cleanup;
            };

            char *end;
            errno = 0;
            unsigned long long val = strtoull(line.buffer, &end, 16);

            if (end == line.buffer || errno == ERANGE)
            {
                puts("invalid chunk size");
                goto cleanup;
            }

            if (val == 0)
            {
                read_line(&line, s);
                break;
            }

            // printf("bytes: %d\n", val);

            size_t total = val;
            while (total)
            {
                size_t want = total < sizeof(res_buf) ? total : sizeof(res_buf);
                rn = read_exact(s, res_buf, want);
                if (rn == 0)
                {
                    puts("response truncated");
                    goto cleanup;
                }
                if (rn < 0)
                {
                    perror("read");
                    goto cleanup;
                }
                fwrite(res_buf, 1, rn, dfile);
                down_n += rn;
                total -= rn;
                req.on_progress(down_n, 0);
            }

            rn = read_exact(s, res_buf, 2);
            if (rn == 0)
            {
                puts("response truncated");
                goto cleanup;
            }
            if (rn < 0)
            {
                perror("read");
                goto cleanup;
            }
        }
    }
    else
    {
        size_t down_n = 0;
        while ((rn = read_exact(s, res_buf, sizeof(res_buf))) > 0)
        {
            fwrite(res_buf, 1, rn, dfile);
            down_n += rn;
            req.on_progress(down_n, 0);
        }
    }

    fflush(dfile);

cleanup:
    if (line.buffer)
        free(line.buffer);
    if (dfile)
        fclose(dfile);

    return 0;
}

void on_progress(size_t received, size_t total)
{
    if (total)
        printf("\r%zu/%zu", received, total);
    else
        printf("\r%zu", received);
    fflush(stdout);
}

int main()
{
    // http://httpbingo.org/image/jpeg
    // http://download.freebsd.org/snapshots/arm64/14.4-STABLE/kernel.txz
    http_req_t req = {.url = "http://download.freebsd.org/snapshots/arm64/14.4-STABLE/kernel.txz",
                      .on_progress = on_progress,
                      .sink = NULL};
    http_get(req);
}