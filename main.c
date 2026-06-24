#include <stdio.h>

#include "http_client.h"

static void
on_progress(size_t received, size_t total)
{
    if (total)
        printf("\r%zu/%zu", received, total);
    else
        printf("\r%zu", received);
    fflush(stdout);
}

int
main(int argc, char **argv)
{
    http_req_t req;
    int ret;

    if (argc != 2)
    {
        fprintf(stderr, "http_client: %s: usage: http_client URL\n",
                http_error_name(HTTP_ERR_USAGE));
        return HTTP_ERR_USAGE;
    }

    req = (http_req_t){.url = argv[1],
                       .on_progress = on_progress,
                       .sink = NULL};
    ret=http_get(req);
    printf("\n");
    return ret;
}
