#ifndef HTTP_FILE_SINK_H
#define HTTP_FILE_SINK_H

#include "http_client.h"

struct http_file_sink
{
    sink_t sink;
    int fd;
};

void http_file_sink_init(struct http_file_sink *fs);

#endif
