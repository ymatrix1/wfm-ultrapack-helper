BIN := wfm-ultrapack-helper.elf
LINUX_BIN := wfm-ultrapack-helper-linux

SRCS := src/main.c src/exfat_engine.c src/convert_engine.c src/miniz.c src/crypto.c src/rsa.c src/pkg_reader.c src/fih_reader.c src/kraken.c
OBJS := $(SRCS:.c=.o)
LINUX_OBJS := $(SRCS:.c=.linux.o)

HOST_CC ?= cc
CFLAGS := -O2 -Wall -Wextra -pthread -Isrc
LDFLAGS := -pthread

# Sanitizer builds: make linux SAN=address,undefined   or   make linux SAN=thread
SAN ?=
ifneq ($(SAN),)
CFLAGS += -fsanitize=$(SAN) -fno-omit-frame-pointer -g
LDFLAGS += -fsanitize=$(SAN)
endif

# If PS5_PAYLOAD_SDK is set, include prospero.mk for ps5 or default goals
ifdef PS5_PAYLOAD_SDK
  ifeq ($(filter linux clean,$(MAKECMDGOALS)),)
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
  endif
endif

PS5_CFLAGS := -O2 -Wall -Wextra -Isrc -pthread
PS5_LDFLAGS := -pthread

.PHONY: all linux ps5 clean

all: $(BIN)

linux: $(LINUX_BIN)

ps5: $(BIN)

$(BIN): $(OBJS)
ifdef PS5_PAYLOAD_SDK
	$(CC) $(PS5_CFLAGS) $(OBJS) -o $@ $(PS5_LDFLAGS)
	$(PS5_PAYLOAD_SDK)/bin/prospero-strip $@
else
	@echo "Notice: PS5_PAYLOAD_SDK not set, compiling linux binary with host cc"
	$(HOST_CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)
endif

$(LINUX_BIN): $(LINUX_OBJS)
	$(HOST_CC) $(CFLAGS) $(LINUX_OBJS) -o $@ $(LDFLAGS)

%.linux.o: %.c
	$(HOST_CC) $(CFLAGS) -c $< -o $@

%.o: %.c
ifdef PS5_PAYLOAD_SDK
	$(CC) $(PS5_CFLAGS) -c $< -o $@
else
	$(HOST_CC) $(CFLAGS) -c $< -o $@
endif

clean:
	rm -f $(BIN) $(LINUX_BIN) src/*.o src/*.linux.o
