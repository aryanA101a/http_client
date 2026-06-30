#include <stdio.h>

#include "http_file_sink.h"
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
    struct http_file_sink file_sink;
    http_req_t req;
    int ret;

    if (argc != 2)
    {
        fprintf(stderr, "http_client: %s: usage: http_client URL\n",
                http_error_name(HTTP_ERR_USAGE));
        return HTTP_ERR_USAGE;
    }

    http_file_sink_init(&file_sink);

    req = (http_req_t){.url = argv[1],
                       .sink = &file_sink.sink,
                       .on_progress = on_progress};
    ret = http_get(req);
    printf("\n");
    return ret;
}
