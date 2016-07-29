# Checks if /usr/include/openssl/whrlpool.h exists, and set a define if it
# doesn't.
INCLUDE_OPENSSL		:= /usr/include/openssl
INCLUDE_WHIRLPOOL	:= whrlpool.h
ifneq ($(shell ls $(INCLUDE_OPENSSL)/$(INCLUDE_WHIRLPOOL) 2>/dev/null), $(INCLUDE_OPENSSL)/$(INCLUDE_WHIRLPOOL))
WHIRLPOOL	:= -DDISABLE_WHIRLPOOL
endif

# Capture the operating system name for use by the preprocessor.
OS		:= $(shell uname | tr '/[[:lower:]]' '_[[:upper:]]')

# These are the specifications of the toolchain
CC		:= gcc
CFLAGS		:= -std=c89 -g -oS -Wall -Werror -Wno-deprecated
CPPFLAGS	:= -D_DEFAULT_SOURCE -D$(OS) $(WHIRLPOOL)
LDFLAGS		:= -lssl -lcrypto

BIN_MAIN	:= hash_extender
BIN_TEST	:= hash_extender_test
BINS		:= $(BIN_MAIN) $(BIN_TEST)

SRCS		:= $(wildcard *.c)
OBJS		:= $(patsubst %.c,%.o,$(SRCS))
OBJS_MAIN	:= $(filter-out $(BIN_TEST).o,$(OBJS))
OBJS_TEST	:= $(filter-out $(BIN_MAIN).o,$(OBJS))

all: $(BINS)

$(BIN_MAIN): $(OBJS_MAIN)
	@echo [LD] $@
	@$(CC) $(CFLAGS) -o $(BIN_MAIN) $(OBJS_MAIN) $(LDFLAGS)

$(BIN_TEST): $(OBJS_TEST)
	@echo [LD] $@
	@$(CC) $(CFLAGS) -o $(BIN_TEST) $(OBJS_TEST) $(LDFLAGS)

%.o: %.c
	@echo [CC] $@
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

clean:
	@echo [RM] \*.o
	@rm -f $(OBJS)
	@echo [RM] $(BIN_MAIN)
	@rm -f $(BIN_MAIN)
	@echo [RM] $(BIN_TEST)
	@rm -f $(BIN_TEST)
