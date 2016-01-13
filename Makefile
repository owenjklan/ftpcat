CC=gcc
CFLAGS=-Wall -O2
OBJS=ftpcat.o

.c.o:
	$(CC) -c $< -o $@ $(CFLAGS)

all: $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o ftpcat
	strip ftpcat

static: $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o ftpcat -static
	strip ftpcat

clean:
	rm -f ftpcat
	rm -f *.o
	rm -f ./*~

install:
	cp ftpcat /usr/local/bin
	cp ftpcat.1.gz /usr/man/man1
