#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

void print_addrinfo(struct addrinfo *ai)
{
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];

    int e = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                        host, sizeof(host),
                        serv, sizeof(serv),
                        NI_NUMERICHOST | NI_NUMERICSERV);

    if (e != 0)
    {
        printf("getnameinfo: %s\n", gai_strerror(e));
        return;
    }

    printf("family=%d socktype=%d protocol=%d addr=%s port=%s\n",
           ai->ai_family,
           ai->ai_socktype,
           ai->ai_protocol,
           host,
           serv);
}

int main()
{
    url_t url;
    struct addrinfo *dns_res, *dns_res0;
    char req_buf[6114];
    char res_buf[4096];
    int n = 0;
    int rn = 0;
    int e;

    parse_url("http://httpbingo.org/get", &url);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    e = getaddrinfo(url.hostname, url.protocol, &hints, &dns_res0);
    if (e != 0)
    {
        printf("%s\n", gai_strerror(e));
        return 1;
    }

    int s = -1;
    for (dns_res = dns_res0; dns_res; dns_res = dns_res->ai_next)
    {
        print_addrinfo(dns_res);

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

        printf("connected!\n");
        break;
    }

    if (s < 0)
    {
        err(1, "%s", "cannot connect");
    }
    freeaddrinfo(dns_res0);

    n = snprintf(req_buf, sizeof(req_buf), "GET %s HTTP/1.1\r\n"
                                           "Host: %s\r\n"
                                           "Connection: close\r\n"
                                           "User-Agent: aryan-http-client/0.1\r\n"
                                           "Accept: */*\r\n"
                                           "\r\n",
                 url.path, url.hostname);
    printf("%s", req_buf);
    write(s, req_buf, n);

    while ((rn = read(s, res_buf, sizeof(res_buf))) > 0)
    {
        fwrite(res_buf, 1, rn, stdout);
    }

    return 0;
}