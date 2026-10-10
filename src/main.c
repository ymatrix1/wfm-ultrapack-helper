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
#include "convert_engine.h"

static int g_running = 1;

typedef struct client_context {
  int fd;
  uint64_t request_id;
  volatile bool cancel_requested;
} client_context_t;

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

static void on_convert_progress(uint64_t total, uint64_t done, void *user_data) {
  client_context_t *ctx = (client_context_t *)user_data;
  unsigned char prog[16];
  put64(prog, total);
  put64(prog + 8, done);
  send_frame(ctx->fd, WUP_MSG_PROGRESS, ctx->request_id, prog, sizeof(prog));
}

static bool check_cancel(void *user_data) {
  client_context_t *ctx = (client_context_t *)user_data;
  return ctx->cancel_requested;
}

typedef struct worker_job {
  client_context_t *ctx;
  char source[2048];
  char destination[2048];
  char format[64];
  uint64_t request_id;
} worker_job_t;

#include <signal.h>

static void *conversion_worker_thread(void *arg) {
  worker_job_t *job = (worker_job_t *)arg;
  char err_msg[1024] = {0};

  int ret = run_conversion(job->source, job->destination, job->format,
                           on_convert_progress, check_cancel,
                           job->ctx, err_msg, sizeof(err_msg));

  if (ret == 0) {
    send_frame(job->ctx->fd, WUP_MSG_DONE, job->request_id, NULL, 0);
  } else {
    const char *resp = err_msg[0] ? err_msg : "Conversion failed";
    send_frame(job->ctx->fd, WUP_MSG_ERROR, job->request_id, resp, (uint32_t)strlen(resp));
  }

  free(job);
  return NULL;
}

static void *
handle_client(void *arg) {
  int fd = (int)(intptr_t)arg;
  wup_frame_t frame;
  char payload[8192];
  memset(&frame, 0, sizeof(frame));
  memset(payload, 0, sizeof(payload));

  client_context_t *ctx = (client_context_t *)calloc(1, sizeof(client_context_t));
  if (!ctx) {
    close(fd);
    return NULL;
  }
  ctx->fd = fd;
  ctx->request_id = 0;
  ctx->cancel_requested = false;
  pthread_t worker_tid = 0;
  bool worker_running = false;

  while (g_running) {
    int ret = recv_frame(fd, &frame, payload, sizeof(payload));
    if (ret <= 0) break;

    ctx->request_id = frame.request_id;

    if (frame.type == WUP_MSG_PING) {
      send_frame(fd, WUP_MSG_PONG, frame.request_id, NULL, 0);
    } else if (frame.type == WUP_MSG_CANCEL) {
      ctx->cancel_requested = true;
    } else if (frame.type == WUP_MSG_CONVERT) {
      /* Reset cancellation for fresh job */
      ctx->cancel_requested = false;
      send_frame(fd, WUP_MSG_ACCEPTED, frame.request_id, NULL, 0);

      worker_job_t *job = (worker_job_t *)calloc(1, sizeof(worker_job_t));
      if (!job) {
        const char *err = "Out of memory";
        send_frame(fd, WUP_MSG_ERROR, frame.request_id, err, (uint32_t)strlen(err));
        continue;
      }

      job->ctx = ctx;
      job->request_id = frame.request_id;
      strncpy(job->format, "ffpfsc", sizeof(job->format) - 1);

      char *line1 = strtok(payload, "\n");
      char *line2 = strtok(NULL, "\n");
      char *line3 = strtok(NULL, "\n");

      if (line1) strncpy(job->source, line1, sizeof(job->source) - 1);
      if (line2) strncpy(job->destination, line2, sizeof(job->destination) - 1);
      if (line3) strncpy(job->format, line3, sizeof(job->format) - 1);

      if (pthread_create(&worker_tid, NULL, conversion_worker_thread, job) != 0) {
        free(job);
        const char *err = "Failed to spawn conversion thread";
        send_frame(fd, WUP_MSG_ERROR, frame.request_id, err, (uint32_t)strlen(err));
      } else {
        worker_running = true;
      }
    }
  }

  /* If client disconnected mid-task, cancel active worker and join it */
  ctx->cancel_requested = true;
  if (worker_running) {
    pthread_join(worker_tid, NULL);
  }

  close(fd);
  free(ctx);
  return NULL;
}

int main(void) {
  int server_fd;
  struct sockaddr_un addr;

  /* Prevent process termination when writing to closed sockets */
  signal(SIGPIPE, SIG_IGN);

  /* Set up log file in /data/wfm/helper.log if directory exists */
  mkdir("/data", 0777);
  mkdir("/data/wfm", 0777);
  FILE *log_fp = fopen("/data/wfm/helper.log", "a");
  if (log_fp) {
    dup2(fileno(log_fp), STDOUT_FILENO);
    dup2(fileno(log_fp), STDERR_FILENO);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
  }

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
  if (log_fp) fclose(log_fp);
  return 0;
}
