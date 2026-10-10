#pragma once

#include <stdint.h>
#include <stddef.h>

#define WUP_HEADER_MAGIC "WUPH"
#define WUP_HEADER_SIZE 20U
#define WUP_MAX_PAYLOAD (1024U * 1024U)

#ifdef __linux__
#define WUP_HELPER_SOCKET "/tmp/wfm-ultrapack-helper.sock"
#else
#define WUP_HELPER_SOCKET "/system_tmp/wfm-ultrapack-helper.sock"
#endif

#define WUP_HELPER_ELF "/data/wfm/wfm-ultrapack-helper.elf"
#define WUP_ELFLDR_PORT 9021

/* Protocol message types */
#define WUP_MSG_PING             1U
#define WUP_MSG_PONG             2U
#define WUP_MSG_CONVERT          10U
#define WUP_MSG_CANCEL           11U
#define WUP_MSG_STATUS           12U

#define WUP_MSG_ACCEPTED         20U
#define WUP_MSG_PROGRESS         21U
#define WUP_MSG_CURRENT_FILE     22U
#define WUP_MSG_DONE             24U
#define WUP_MSG_ERROR            25U

/* Conversion target formats */
typedef enum wup_target_format {
  WUP_FORMAT_FFPFSC = 1,
  WUP_FORMAT_FFPFS  = 2,
  WUP_FORMAT_PKG    = 3,
  WUP_FORMAT_FOLDER = 4,
} wup_target_format_t;

typedef struct wup_frame {
  uint16_t type;
  uint16_t flags;
  uint32_t payload_size;
  uint64_t request_id;
} wup_frame_t;
