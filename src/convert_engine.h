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

/* .ffpfsc = PFS image (header, inodes, flat path table) with ONE inner file whose data is a PFSC container.
 * Convert an exFAT or raw image to .ffpfsc, streaming in 1 MiB chunks. The inner file is named after the
 * source (ultrapack rename rules). Set WUP_FIXED_TIME=<seconds> for deterministic PFS timestamps. */
int convert_image_to_ffpfsc(const char *in_image_path, const char *out_ffpfsc_path,
                            convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                            void *user_data, char *err_msg, size_t err_len);

/* Listing + random-access source -> .ffpfsc, zero staging (same PFSC sink as folder -> ffpfsc).
 * The output file is removed on failure/cancel. Returns 0, -1 on error, -2 on cancel. */
int convert_listing_to_ffpfsc(const exfat_listing_entry_t *entries, size_t count,
                              const exfat_src_ops_t *ops, void *ops_ctx, const char *out_ffpfsc_path,
                              convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                              void *user_data, char *err_msg, size_t err_len);

/* Same, naming the inner file <title_id>.exfat (NULL/empty = derive from the output file name). */
int convert_listing_to_ffpfsc_ex(const exfat_listing_entry_t *entries, size_t count,
                                 const exfat_src_ops_t *ops, void *ops_ctx, const char *out_ffpfsc_path,
                                 const char *title_id,
                                 convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                                 void *user_data, char *err_msg, size_t err_len);

/* High-level conversion dispatcher from source -> target format */
/* Same as run_conversion, with an optional PKG passcode (NULL = default 32 x '0'). */
int run_conversion_ex(const char *source_path, const char *dest_path, const char *format_str,
                      const char *passcode,
                      convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                      void *user_data, char *err_msg, size_t err_len);

int run_conversion(const char *source_path, const char *dest_path, const char *format_str,
                   convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                   void *user_data, char *err_msg, size_t err_len);

#ifdef __cplusplus
}
#endif
