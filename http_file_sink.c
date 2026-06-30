#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "http_file_sink.h"

static int
write_fd_exact(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    size_t off;

    off = 0;
    while (off < n)
    {
        ssize_t wn;

        wn = write(fd, p + off, n - off);
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

static int
http_file_sink_write(struct http_sink *sink, const void *data, size_t len)
{
    struct http_file_sink *fs;

    fs = (struct http_file_sink *)sink;
    return write_fd_exact(fs->fd, data, len);
}

static int
http_file_sink_open(struct http_sink *sink, const char *name)
{
    struct http_file_sink *fs;

    fs = (struct http_file_sink *)sink;
    fs->fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fs->fd == -1)
    {
        fprintf(stderr, "http_client: %s: %s\n",
                http_error_name(HTTP_ERR_IO), name);
        return HTTP_ERR_IO;
    }

    return HTTP_OK;
}

static void
http_file_sink_close(struct http_sink *sink)
{
    struct http_file_sink *fs;

    fs = (struct http_file_sink *)sink;
    if (fs->fd >= 0)
    {
        close(fs->fd);
        fs->fd = -1;
    }
}

void
http_file_sink_init(struct http_file_sink *fs)
{
    *fs = (struct http_file_sink){
        .sink = {
            .open = http_file_sink_open,
            .write = http_file_sink_write,
            .close = http_file_sink_close,
        },
        .fd = -1,
    };
}
