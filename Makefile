#
# Catcrypt, simple RSA/PKE for C
# Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
# Licensed under GPLv3 License
# See LICENSE for more info
#

CC = gcc
SOURCES = $(filter-out $(shell find . -path "*/examples/*"), $(shell find ./src -name "*.c"))
HEADERS = $(filter-out $(shell find . -path "*/examples/*"), $(shell find ./include -name "*.h"))
OBJ = rsa.o string.o ref.o util.o
EXISTING_EXECUTABLES = $(shell find . -iname "*.exe")
TEST_EXECUTABLES =  examples/test/test.exe
TEST_SOURCES = $(shell find . -iname "*.c")

CFLAGS = -std=c17 \
		 -O3 \
		 -I. \
		 -g \
		 -Wno-unused-command-line-argument

ifeq ($(OS), Windows_NT)
	RM = rm -rf
else
	RM = rm -rf
endif

.PHONY: all clean test

all: rsa.o
	@make -C examples/test

util.o: src/util.c include/util.h
	$(CC) -c -o $@ $(filter-out include/util.h, $<) $(CFLAGS) $(LDFLAGS)

ref.o: src/ref.c include/ref.h
	$(CC) -c -o $@ $(filter-out include/ref.h, $<) $(CFLAGS) $(LDFLAGS)

string.o: src/string.c include/string.h
	$(CC) -c -o $@ $(filter-out include/string.h, $<) $(CFLAGS) $(LDFLAGS)

rsa.o: src/rsa.c include/rsa.h string.o ref.o util.o
	$(CC) -c -o $@ $(filter-out include/rsa.h, $<) $(CFLAGS) $(LDFLAGS)

clean:
	$(RM) $(OBJ)
	$(RM) $(EXISTING_EXECUTABLES)

test: all
	./examples/test/test.exe