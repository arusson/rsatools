#
# rsatools, a set of cryptanalysis tools against RSA
# Copyright (C) 2022 A. Russon
#

CC = gcc
CFLAGS = -Wall -Wextra -O2 -flto
LDFLAGS = -lpari

INCLDIR = include
BINDIR = bin
SRCDIR = prgm

BINS = rsa_single rsa_partial_p rsa_partial_d
DEPSDIRS = rsa-single rsa-coppersmith utils

SRC = $(wildcard $(SRCDIR)/*.c)
SRCDEPS = $(wildcard *.c $(foreach fd, $(DEPSDIRS), $(fd)/*.c))
OBJDEPS = $(SRCDEPS:%.c=%.o)

.PHONY: clean info

all: $(BINS)

$(BINS): %: $(BINDIR) $(OBJDEPS)
	$(CC) $(CFLAGS) -o $(BINDIR)/$@ $(SRCDIR)/$@.c $(OBJDEPS) $(LDFLAGS) -I$(INCLDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -I$(INCLDIR)

clean:
	rm $(OBJDEPS)

