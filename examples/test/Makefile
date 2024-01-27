#
# catcrypt is a json parser for C
#
# https://github.com/rohanrhu/catcrypt
# https://oguzhaneroglu.com/projects/catcrypt/
#
# Licensed under MIT
# Copyright (C) 2023, Oğuzhan Eroğlu (https://oguzhaneroglu.com/) <rohanrhu2@gmail.com>
#

CC = gcc
CFLAGS = -std=c17 \
		 -I../../thirdparty/gmp-6.3.0 \
		 -I../../ \
		 -g

ifeq ($(OS), Windows_NT)
	RM = rm -rf
else
	RM = rm -rf
endif

.PHONY: all clean test

all: test.exe

../../thirdparty/gmp-6.3.0/.libs/libgmp.a:
	@make -C ../../thirdparty/gmp-6.3.0

test.exe: test.c ../../rsa.o ../../string.o ../../ref.o ../../util.o ../../thirdparty/gmp-6.3.0/.libs/libgmp.a
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	$(RM) $(EXECUTABLE)