#include "logger.h"

#include <sys/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef DISABLE_LOGGING

void logger(const char *filename, int line, char level, const char *fmt, ...)
{
    struct timeval tv;
    char buffer[1024];
    va_list ap;
    int when;
    int ret;

    gettimeofday(&tv, NULL);
    when = (tv.tv_sec - timezone) % 86400;
    ret = snprintf(buffer, sizeof(buffer), "%c %02d:%02d:%02d.%06ld %s [%s:%d]\n",
            level, when / 3600, when % 3600 / 60, when % 60, tv.tv_usec,
            fmt, filename, line);

    if (ret < 0 || (size_t)ret >= sizeof(buffer)) {
        abort(); /* BUG */
    }

    va_start(ap, fmt);
    ret = vfprintf(stderr, buffer, ap);
    va_end(ap);
}

#endif
