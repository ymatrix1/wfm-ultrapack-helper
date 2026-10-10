/* Exercise the real worker, observing its passcode before response and free. */
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>

static ssize_t test_send(int fd, const void *buf, size_t len, int flags);
static void test_free(void *ptr);

#define main helper_main
#define send test_send
#define free test_free
#include "../src/main.c"
#undef main
#undef send
#undef free

static worker_job_t *active_job;
static unsigned char original_passcode[64];
static int conversion_result, conversion_called, response_type, job_freed;

static void assert_passcode_cleared(void) {
    for (size_t i = 0; i < sizeof(active_job->passcode); i++) {
        assert(active_job->passcode[i] == 0);
    }
}

int run_conversion_ex(const char *source, const char *dest, const char *format,
                      const char *passcode, convert_progress_cb progress,
                      convert_cancel_cb cancel, void *user_data,
                      char *err_msg, size_t err_len) {
    (void)source; (void)dest; (void)format; (void)progress; (void)cancel;
    assert(user_data == active_job);
    assert(!memcmp(active_job->passcode, original_passcode, sizeof original_passcode));
    assert(passcode == (active_job->passcode[0] ? active_job->passcode : NULL));
    conversion_called++;
    if (conversion_result) snprintf(err_msg, err_len, "Test conversion error");
    return conversion_result;
}

static ssize_t test_send(int fd, const void *buf, size_t len, int flags) {
    (void)fd; (void)flags;
    assert(conversion_called == 1);
    /* The wipe must precede even the first terminal response. */
    assert_passcode_cleared();
    if (!response_type) {
        assert(len == WUP_HEADER_SIZE);
        response_type = get16((const unsigned char *)buf + 4);
    }
    return (ssize_t)len;
}

static void test_free(void *ptr) {
    assert(ptr == active_job);
    assert_passcode_cleared();
    assert(!active_job->ctx->is_busy);
    assert(response_type == (conversion_result ? WUP_MSG_ERROR : WUP_MSG_DONE));
    job_freed++;
    free(ptr);
    active_job = NULL;
}

int main(void) {
    const int results[] = {0, -1, -2}; /* success, failure, cancellation */
    for (size_t i = 0; i < sizeof results / sizeof results[0]; i++) {
        for (int empty = 0; empty < 2; empty++) {
            client_context_t ctx = {0};
            assert(!pthread_mutex_init(&ctx.send_lock, NULL));
            ctx.is_busy = true;
            active_job = calloc(1, sizeof *active_job);
            assert(active_job);
            active_job->ctx = &ctx;
            /* Nonzero tail bytes catch wipes that only use strlen(). */
            memset(active_job->passcode, 0xa5, sizeof active_job->passcode);
            strcpy(active_job->passcode, empty ? "" : "0123456789abcdef0123456789abcdef");
            memcpy(original_passcode, active_job->passcode, sizeof original_passcode);
            conversion_result = results[i];
            conversion_called = response_type = job_freed = 0;
            assert(conversion_worker_thread(active_job) == NULL);
            assert(job_freed == 1);
            assert(!pthread_mutex_destroy(&ctx.send_lock));
        }
    }
    puts("worker passcode tests: 6 passed");
    return 0;
}
