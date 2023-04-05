#ifndef LOGGER_H
#define LOGGER_H

#ifndef DISABLE_LOGGING

extern void logger(const char *filename,
                   int line,
                   char level,
                   const char *fmt, ...) __attribute__((format (printf, 4, 5)));

#ifndef NDEBUG
#define LOGD(...) logger(__FILE__, __LINE__, 'D', __VA_ARGS__)
#else
#define LOGD(...)
#endif

#define LOGI(...) logger(__FILE__, __LINE__, ' ', __VA_ARGS__)
#define LOGW(...) logger(__FILE__, __LINE__, 'W', __VA_ARGS__)
#define LOGE(...) logger(__FILE__, __LINE__, 'E', __VA_ARGS__)

#else

#define LOGD(...)
#define LOGI(...)
#define LOGW(...)
#define LOGE(...)

#endif

#endif /* LOGGER_H */
