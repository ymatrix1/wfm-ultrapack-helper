#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "protocol.h"
#include "exfat_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PFSC outer container constants */
#define PFSC_MAGIC 0x43534650U /* 'PFSC' */
#define PFSC_LOGICAL_BLOCK_SIZE 0x10000U /* 64 KiB */
#define PFSC_HEADER_SIZE 0x30U
#define PFSC_OFFSET_ENTRY_SIZE 0x8U
#define PFSC_BLOCK_OFFSETS_OFFSET 0x400U
#define PFSC_INITIAL_DATA_OFFSET 0x10000U

/* Convert an exFAT or raw image to a compressed .ffpfsc archive streaming in 32 MiB buffers */
int convert_image_to_ffpfsc(const char *in_image_path, const char *out_ffpfsc_path,
                            convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                            void *user_data, char *err_msg, size_t err_len);

/* High-level conversion dispatcher from source -> target format */
int run_conversion(const char *source_path, const char *dest_path, const char *format_str,
                   convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                   void *user_data, char *err_msg, size_t err_len);

#ifdef __cplusplus
}
#endif
