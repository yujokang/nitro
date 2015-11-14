include ../common.mk

CPPFLAGS=-I../
LIBTARGET_FILE=../libnitro.a
LDFLAGS+=$(LIBTARGET_FILE)

BASIC_OBJECTS=basic_main.o
OBJS=$(BASIC_OBJECTS)
BINS=basic

TARGETS=$(OBJS) $(BINS)

all: $(TARGETS)

%.o: %.c
	$(CC) -c $< $(CFLAGS) $(CPPFLAGS) -o $@

basic: $(BASIC_OBJECTS)
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@

clean:
	rm -rf $(TARGETS)
