CC = gcc

TARGET = nitro
LIBTARGET = libnitro
LIBTARGET_FILE = $(LIBTARGET).a
CFLAGS = -g -Wall
DEPS = libnitro.h
LIBOBJ = libnitro.o
OBJ = nitro_main.o $(LIBOBJ)

.PHONY: examples default all clean

default: $(TARGET) $(LIBTARGET) examples
all: default

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

$(LIBTARGET): 
	ar -cvq $(LIBTARGET).a $(LIBOBJ)

examples: $(LIBTARGET_FILE)
	make -C $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
	-rm -f $(LIBTARGET).a
	make -C examples clean
