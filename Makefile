BIN := wfm-ultrapack-helper.elf
LINUX_BIN := wfm-ultrapack-helper-linux

SRCS := src/main.c src/exfat_engine.c src/convert_engine.c

HOST_CC ?= cc
CFLAGS := -O2 -Wall -Wextra -pthread -Isrc
LDFLAGS := -pthread -lz

ifneq ($(filter-out linux clean,$(MAKECMDGOALS)),)
  ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
  endif
endif

PS5_CFLAGS := -O2 -Wall -Wextra -Isrc -pthread
PS5_LDFLAGS := -pthread

all: $(BIN)

linux: $(LINUX_BIN)

ps5: $(BIN)

$(BIN): $(SRCS)
ifdef PS5_PAYLOAD_SDK
	$(CC) $(PS5_CFLAGS) $(SRCS) -o $@ $(PS5_LDFLAGS)
	$(PS5_PAYLOAD_SDK)/bin/prospero-strip $@
else
	@echo "Notice: PS5_PAYLOAD_SDK not set, compiling linux binary as placeholder"
	$(HOST_CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)
endif

$(LINUX_BIN): $(SRCS)
	$(HOST_CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN) $(LINUX_BIN)
