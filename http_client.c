#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <err.h>

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
    int hn = 0;
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

int http_get(http_req_t req)
{
    url_t p_url;
    struct addrinfo *dns_res, *dns_res0;
    char req_buf[6114];
    char res_buf[256];
    char *line = NULL;
    int n = 0;
    size_t rn = 0;
    size_t hn = 0;
    int l_cap = 0;
    int e;
    size_t c_len = -1;
    int chunked = 0;
    FILE *sfp = NULL;
    FILE *dfile = NULL;

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

    sfp = fdopen(s, "r+");
    if (!sfp)
    {
        perror("fdopen");
        goto cleanup;
    }

    char version[16];
    int status;

    getline(&line, &l_cap, sfp);
    printf("%s", line);
    if (sscanf(line, "%15s %d", version, &status) != 2)
    {
        puts("bad status");
        goto cleanup;
    }

    printf("version:%s status:%d\n\n", version, status);

    char *col = NULL;
    char *h_key = NULL;
    char *h_val = NULL;
    while ((hn = getline(&line, &l_cap, sfp)) > 0)
    {

        col = strchr(line, ':');

        if (col)
        {
            *col = '\0';

            h_key = line;
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

        if (strcmp(line, "\r\n") == 0)
            break;
    }

    printf("\n");

    if (c_len >= 0)
    {
        size_t total = c_len;
        while (total)
        {
            size_t want = total < sizeof(res_buf) ? total : sizeof(res_buf);
            rn = fread(res_buf, 1, want, sfp);
            if (rn == 0)
            {
                puts("response truncated");
                goto cleanup;
            }
            fwrite(res_buf, 1, rn, dfile);
            total -= rn;
            req.on_progress(c_len - total, c_len);
        }
    }
    else if (chunked)
    {
        size_t down_n = 0;
        while (1)
        {
            size_t ch_len = -1;
            if ((hn = getline(&line, &l_cap, sfp)) == 0)
            {
                puts("request truncated");
                goto cleanup;
            };

            char *end;
            long val;
            val = strtol(line, &end, 16);
            if (end == line)
            {
                puts("invalid value");
                goto cleanup;
            }
            if (val == 0)
            {
                getline(&line, &l_cap, sfp);
                break;
            }

            // printf("bytes: %d\n", val);

            if ((rn = fread(res_buf, 1, val, sfp)) > 0)
            {
                fwrite(res_buf, 1, rn, dfile);
                fread(res_buf, 1, 2, sfp);
                down_n += rn;
                req.on_progress(down_n, 0);
            }
        }
    }
    else
    {
        size_t down_n = 0;
        while ((rn = fread(res_buf, 1, sizeof(res_buf), sfp)) > 0)
        {
            fwrite(res_buf, 1, rn, dfile);
            down_n += rn;
            req.on_progress(down_n, 0);
        }
    }

    fflush(dfile);

cleanup:
    if (sfp)
        fclose(sfp);
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
    http_req_t req = {.url = "http://download.freebsd.org/snapshots/arm64/14.4-STABLE/kernel.txz",
                      .on_progress = on_progress,
                      .sink = NULL};
    http_get(req);
}