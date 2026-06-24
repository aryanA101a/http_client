#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>

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

const char *http_error_name(http_error_t err);
int http_get(http_req_t req);

#endif
