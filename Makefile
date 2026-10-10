BIN := wfm-ultrapack-helper.elf
LINUX_BIN := wfm-ultrapack-helper-linux

SRCS := src/main.c

CFLAGS := -O2 -Wall -Wextra -pthread -Isrc
LDFLAGS := -pthread

all: $(LINUX_BIN)

linux: $(LINUX_BIN)

$(LINUX_BIN): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN) $(LINUX_BIN)
