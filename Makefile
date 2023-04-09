.PHONY: all clean

CPPFLAGS ?=

CFLAGS ?=
CFLAGS += -ggdb
CFLAGS += -Wall -Wextra

LDFLAGS ?=
LDFLAGS += -lcrypto
LDFLAGS += -lmicrohttpd

ifneq ($(debug),1)
CPPFLAGS += -DNDEBUG
CPPFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -O2
CFLAGS += -fpie
CFLAGS += -flto
CFLAGS += -Wstack-protector -fstack-protector-all
LDFLAGS += -Wl,-pie
LDFLAGS += -Wl,-z,now
LDFLAGS += -Wl,-z,defs
LDFLAGS += -Wl,-z,relro
endif

all: scep
clean:
	rm -f scep *.o

scep: main.c.o scep.c.o httpd.c.o logger.c.o
	$(CC) -o $@ $^ $(LDFLAGS)

main.c.o: main.c scep.h httpd.h logger.h
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)

scep.c.o: scep.c scep.h logger.h
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)

httpd.c.o: httpd.c httpd.h logger.h
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)

logger.c.o: logger.c logger.h
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)
