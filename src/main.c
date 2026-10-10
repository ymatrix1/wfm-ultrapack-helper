#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <poll.h>
#include <pthread.h>

#include "protocol.h"

static int g_running = 1;

static void
put16(unsigned char *p, uint16_t v) {
  p[0] = (unsigned char)(v >> 8);
  p[1] = (unsigned char)v;
}

static void
put32(unsigned char *p, uint32_t v) {
  p[0] = (unsigned char)(v >> 24);
  p[1] = (unsigned char)(v >> 16);
  p[2] = (unsigned char)(v >> 8);
  p[3] = (unsigned char)v;
}

static void
put64(unsigned char *p, uint64_t v) {
  put32(p, (uint32_t)(v >> 32));
  put32(p + 4, (uint32_t)v);
}

static uint16_t
get16(const unsigned char *p) {
  return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t
get32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t
get64(const unsigned char *p) {
  return ((uint64_t)get32(p) << 32) | get32(p + 4);
}

static int
send_frame(int fd, uint16_t type, uint64_t request_id, const void *payload, uint32_t size) {
  unsigned char header[WUP_HEADER_SIZE];
  memcpy(header, WUP_HEADER_MAGIC, 4);
  put16(header + 4, type);
  put16(header + 6, 0);
  put32(header + 8, size);
  put64(header + 12, request_id);

  if (send(fd, header, sizeof(header), 0) != sizeof(header)) return -1;
  if (size && payload) {
    if (send(fd, payload, size, 0) != (ssize_t)size) return -1;
  }
  return 0;
}

static int
recv_frame(int fd, wup_frame_t *frame, char *payload, size_t cap) {
  unsigned char header[WUP_HEADER_SIZE];
  ssize_t n = recv(fd, header, sizeof(header), MSG_WAITALL);
  if (n <= 0) return (int)n;
  if (n != sizeof(header) || memcmp(header, WUP_HEADER_MAGIC, 4) != 0) {
    errno = EPROTO;
    return -1;
  }
  frame->type = get16(header + 4);
  frame->flags = get16(header + 6);
  frame->payload_size = get32(header + 8);
  frame->request_id = get64(header + 12);

  if (frame->payload_size >= cap) {
    errno = EMSGSIZE;
    return -1;
  }
  if (frame->payload_size) {
    n = recv(fd, payload, frame->payload_size, MSG_WAITALL);
    if (n != (ssize_t)frame->payload_size) return -1;
  }
  payload[frame->payload_size] = '\0';
  return 1;
}

static void *
handle_client(void *arg) {
  int fd = (int)(intptr_t)arg;
  wup_frame_t frame;
  char payload[8192];

  while (g_running) {
    int ret = recv_frame(fd, &frame, payload, sizeof(payload));
    if (ret <= 0) break;

    if (frame.type == WUP_MSG_PING) {
      send_frame(fd, WUP_MSG_PONG, frame.request_id, NULL, 0);
    } else if (frame.type == WUP_MSG_CONVERT) {
      /* Conversion request handling */
      send_frame(fd, WUP_MSG_ACCEPTED, frame.request_id, NULL, 0);

      /* Stream simulated or actual conversion stages */
      unsigned char prog[16];
      uint64_t total = 100;
      uint64_t done = 100;
      put64(prog, total);
      put64(prog + 8, done);
      send_frame(fd, WUP_MSG_PROGRESS, frame.request_id, prog, sizeof(prog));

      /* Done */
      send_frame(fd, WUP_MSG_DONE, frame.request_id, NULL, 0);
    }
  }

  close(fd);
  return NULL;
}

int main(void) {
  int server_fd;
  struct sockaddr_un addr;

  unlink(WUP_HELPER_SOCKET);
  server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("socket");
    return 1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, WUP_HELPER_SOCKET, sizeof(addr.sun_path) - 1);

  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(server_fd);
    return 1;
  }

  chmod(WUP_HELPER_SOCKET, 0777);

  if (listen(server_fd, 8) < 0) {
    perror("listen");
    close(server_fd);
    return 1;
  }

  printf("wfm-ultrapack-helper listening on %s\n", WUP_HELPER_SOCKET);

  while (g_running) {
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
      if (errno == EINTR) continue;
      break;
    }
    pthread_t th;
    pthread_create(&th, NULL, handle_client, (void *)(intptr_t)client_fd);
    pthread_detach(th);
  }

  close(server_fd);
  unlink(WUP_HELPER_SOCKET);
  return 0;
}
