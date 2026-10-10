#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>

#include "protocol.h"
#include "convert_engine.h"

static volatile int g_running = 1;

static void handle_signal(int sig) {
  (void)sig;
  g_running = 0;
}

typedef struct client_context {
  int fd;
  pthread_mutex_t send_lock;
  volatile bool cancel_requested;
  volatile bool is_busy;
  uint64_t last_progress_time_ms;
} client_context_t;

static uint64_t get_time_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

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

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int
send_frame_locked(client_context_t *ctx, uint16_t type, uint64_t request_id, const void *payload, uint32_t size) {
  unsigned char header[WUP_HEADER_SIZE];
  memcpy(header, WUP_HEADER_MAGIC, 4);
  put16(header + 4, type);
  put16(header + 6, 0);
  put32(header + 8, size);
  put64(header + 12, request_id);

  pthread_mutex_lock(&ctx->send_lock);
  if (send(ctx->fd, header, sizeof(header), MSG_NOSIGNAL) != sizeof(header)) {
    pthread_mutex_unlock(&ctx->send_lock);
    return -1;
  }
  if (size && payload) {
    if (send(ctx->fd, payload, size, MSG_NOSIGNAL) != (ssize_t)size) {
      pthread_mutex_unlock(&ctx->send_lock);
      return -1;
    }
  }
  pthread_mutex_unlock(&ctx->send_lock);
  return 0;
}

static int
recv_frame(int fd, wup_frame_t *frame, char **payload_out, size_t *payload_cap) {
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

  if (frame->payload_size > WUP_MAX_PAYLOAD) {
    errno = EMSGSIZE;
    return -1;
  }

  if (frame->payload_size + 1 > *payload_cap) {
    size_t new_cap = frame->payload_size + 4096;
    char *new_buf = (char *)realloc(*payload_out, new_cap);
    if (!new_buf) {
      errno = ENOMEM;
      return -1;
    }
    *payload_out = new_buf;
    *payload_cap = new_cap;
  }

  if (frame->payload_size) {
    n = recv(fd, *payload_out, frame->payload_size, MSG_WAITALL);
    if (n != (ssize_t)frame->payload_size) return -1;
  }
  (*payload_out)[frame->payload_size] = '\0';
  return 1;
}

typedef struct worker_job {
  client_context_t *ctx;
  char source[4096];
  char destination[4096];
  char format[64];
  char passcode[64];   /* optional PKG passcode; never logged or echoed */
  uint64_t request_id;
} worker_job_t;

static void on_convert_progress(uint64_t total, uint64_t done, void *user_data) {
  worker_job_t *job = (worker_job_t *)user_data;
  uint64_t now = get_time_ms();
  /* Throttle progress updates to at most ~4/sec (every 250ms), except at start/completion */
  if (done > 0 && done < total && (now - job->ctx->last_progress_time_ms < 250)) {
    return;
  }
  job->ctx->last_progress_time_ms = now;

  unsigned char prog[16];
  put64(prog, total);
  put64(prog + 8, done);
  send_frame_locked(job->ctx, WUP_MSG_PROGRESS, job->request_id, prog, sizeof(prog));
}

static bool check_cancel(void *user_data) {
  worker_job_t *job = (worker_job_t *)user_data;
  return job->ctx->cancel_requested;
}

static bool is_safe_path(const char *path) {
  if (!path || !path[0]) return false;
  if (path[0] != '/') return false;
  /* Prevent directory traversal */
  if (strstr(path, "/../") || !strcmp(path, "/..") || strstr(path, "/..") == path + strlen(path) - 3) {
    return false;
  }
  /* On PS5 / jailed system, allow typical root locations */
  if (!strncmp(path, "/data", 5) || !strncmp(path, "/user", 5) ||
      !strncmp(path, "/mnt", 4) || !strncmp(path, "/system_tmp", 11) ||
      !strncmp(path, "/tmp", 4)) {
    return true;
  }
  return false;
}

static void *conversion_worker_thread(void *arg) {
  worker_job_t *job = (worker_job_t *)arg;
  char err_msg[1024] = {0};

  int ret = run_conversion_ex(job->source, job->destination, job->format,
                           job->passcode[0] ? job->passcode : NULL,
                           on_convert_progress, check_cancel,
                           job, err_msg, sizeof(err_msg));

  /* Volatile stores prevent the compiler from removing the passcode wipe. */
  volatile unsigned char *passcode_bytes = (volatile unsigned char *)job->passcode;
  for (size_t i = 0; i < sizeof(job->passcode); i++) {
    passcode_bytes[i] = 0;
  }

  if (ret == 0) {
    send_frame_locked(job->ctx, WUP_MSG_DONE, job->request_id, NULL, 0);
  } else {
    const char *resp = err_msg[0] ? err_msg : "Conversion failed";
    send_frame_locked(job->ctx, WUP_MSG_ERROR, job->request_id, resp, (uint32_t)strlen(resp));
  }

  job->ctx->is_busy = false;
  free(job);
  return NULL;
}

static void *
handle_client(void *arg) {
  int fd = (int)(intptr_t)arg;
  wup_frame_t frame;
  size_t payload_cap = 65536;
  char *payload = (char *)malloc(payload_cap);
  if (!payload) {
    close(fd);
    return NULL;
  }

  client_context_t *ctx = (client_context_t *)calloc(1, sizeof(client_context_t));
  if (!ctx) {
    free(payload);
    close(fd);
    return NULL;
  }
  ctx->fd = fd;
  pthread_mutex_init(&ctx->send_lock, NULL);
  ctx->cancel_requested = false;
  ctx->is_busy = false;
  ctx->last_progress_time_ms = 0;
  pthread_t worker_tid = 0;

  while (g_running) {
    int ret = recv_frame(fd, &frame, &payload, &payload_cap);
    if (ret <= 0) break;

    if (frame.type == WUP_MSG_PING) {
      send_frame_locked(ctx, WUP_MSG_PONG, frame.request_id, NULL, 0);
    } else if (frame.type == WUP_MSG_STATUS) {
      const char *st = ctx->is_busy ? "busy" : "idle";
      send_frame_locked(ctx, WUP_MSG_STATUS, frame.request_id, st, (uint32_t)strlen(st));
    } else if (frame.type == WUP_MSG_CANCEL) {
      ctx->cancel_requested = true;
    } else if (frame.type == WUP_MSG_CONVERT) {
      if (ctx->is_busy) {
        const char *err = "Conversion already in progress";
        send_frame_locked(ctx, WUP_MSG_ERROR, frame.request_id, err, (uint32_t)strlen(err));
        continue;
      }

      /* Parse 3 newline-separated parameters without skipping empty fields */
      char *first_nl = strchr(payload, '\n');
      if (!first_nl) {
        const char *err = "Invalid convert payload: missing destination";
        send_frame_locked(ctx, WUP_MSG_ERROR, frame.request_id, err, (uint32_t)strlen(err));
        continue;
      }
      *first_nl = '\0';
      char *src_path = payload;
      char *rem = first_nl + 1;

      char *second_nl = strchr(rem, '\n');
      char *dst_path = rem;
      char *fmt_str = "ffpfsc";
      char *passcode = "";
      if (second_nl) {
        *second_nl = '\0';
        fmt_str = second_nl + 1;
        char *third_nl = strchr(fmt_str, '\n');
        if (third_nl) {
          *third_nl = '\0';
          passcode = third_nl + 1;
        }
      }

      if (!is_safe_path(src_path) || !is_safe_path(dst_path)) {
        const char *err = "Invalid or disallowed path";
        send_frame_locked(ctx, WUP_MSG_ERROR, frame.request_id, err, (uint32_t)strlen(err));
        continue;
      }

      worker_job_t *job = (worker_job_t *)calloc(1, sizeof(worker_job_t));
      if (!job) {
        const char *err = "Out of memory";
        send_frame_locked(ctx, WUP_MSG_ERROR, frame.request_id, err, (uint32_t)strlen(err));
        continue;
      }

      job->ctx = ctx;
      job->request_id = frame.request_id;
      strncpy(job->source, src_path, sizeof(job->source) - 1);
      strncpy(job->destination, dst_path, sizeof(job->destination) - 1);
      strncpy(job->format, fmt_str, sizeof(job->format) - 1);
      strncpy(job->passcode, passcode, sizeof(job->passcode) - 1);
      /* scrub the passcode from the receive buffer */
      memset(passcode, 0, strlen(passcode));

      ctx->cancel_requested = false;
      ctx->is_busy = true;
      ctx->last_progress_time_ms = 0;
      send_frame_locked(ctx, WUP_MSG_ACCEPTED, frame.request_id, NULL, 0);

      pthread_attr_t attr;
      pthread_attr_init(&attr);
      /* Give worker thread 2 MiB explicit stack space to prevent stack overflows */
      pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);

      if (pthread_create(&worker_tid, &attr, conversion_worker_thread, job) != 0) {
        pthread_attr_destroy(&attr);
        ctx->is_busy = false;
        free(job);
        const char *err = "Failed to spawn conversion thread";
        send_frame_locked(ctx, WUP_MSG_ERROR, frame.request_id, err, (uint32_t)strlen(err));
      } else {
        pthread_attr_destroy(&attr);
      }
    } else {
      /* Unknown frame type */
      const char *err = "Unknown message type";
      send_frame_locked(ctx, WUP_MSG_ERROR, frame.request_id, err, (uint32_t)strlen(err));
    }
  }

  /* If client disconnected mid-task, cancel active worker and join it */
  ctx->cancel_requested = true;
  if (ctx->is_busy) {
    pthread_join(worker_tid, NULL);
  }

  close(fd);
  pthread_mutex_destroy(&ctx->send_lock);
  free(ctx);
  free(payload);
  return NULL;
}

int main(void) {
  int server_fd;
  struct sockaddr_un addr;

  /* Prevent process termination when writing to closed sockets */
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

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
#ifndef __linux__
  addr.sun_len = (unsigned char)SUN_LEN(&addr);
  socklen_t addr_len = addr.sun_len;
#else
  socklen_t addr_len = sizeof(addr);
#endif

  if (bind(server_fd, (struct sockaddr *)&addr, addr_len) < 0) {
    perror("bind");
    close(server_fd);
    return 1;
  }

  chmod(WUP_HELPER_SOCKET, 0770);

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
