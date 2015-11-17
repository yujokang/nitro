include ../common.mk

CPPFLAGS=-I../ -I./
LIBTARGET_FILE=../libnitro.a
LDFLAGS+=$(LIBTARGET_FILE)

COMMON_OBJS=user_utils.o
BASIC_OBJECTS=basic_main.o
STRING_PARAMS_OBJS=string_params_main.o
OBJS=$(COMMON_OBJS) $(BASIC_OBJECTS) $(STRING_PARAMS_OBJS)
BINS=basic string_params

TARGETS=$(OBJS) $(BINS)

all: $(TARGETS)

%.o: %.c
	$(CC) -c $< $(CFLAGS) $(CPPFLAGS) -o $@

basic: $(BASIC_OBJECTS) $(COMMON_OBJS)
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@
string_params: $(STRING_PARAMS_OBJS) $(COMMON_OBJS)
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@

clean:
	rm -rf $(TARGETS)
