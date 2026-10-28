#ifndef CAMERA_LUT_STORE_H
#define CAMERA_LUT_STORE_H
#include <stddef.h>
#include <stdint.h>
#include "cube_input.h"

#define CAMERA_LUT_HEADER_BYTES 256u
#define CAMERA_LUT_RECORD_BYTES (CAMERA_LUT_HEADER_BYTES+CAMERA_CUBE_AP_INTEGER_BYTES)
enum camera_lut_store_status {
    CAMERA_LUT_STORE_OK=0, CAMERA_LUT_STORE_INVALID, CAMERA_LUT_STORE_IO,
    CAMERA_LUT_STORE_BUSY, CAMERA_LUT_STORE_UNCERTAIN, CAMERA_LUT_STORE_CORRUPT,
    CAMERA_LUT_STORE_NOT_FOUND, CAMERA_LUT_STORE_CONFLICT
};
struct camera_lut_record_meta {
    uint32_t slot, source_grid, compiled_grid;
    uint32_t bounds_policy, quantization_policy, clamped_nodes, saturated_components;
    uint64_t generation;
    const char *filename, *input_space, *output_space;
};
struct camera_lut_store_result {
    uint64_t generation;
    uint32_t from_backup, renamed_primary, directory_synced;
};
/* Self-contained compiled table plus source identity and color-space labels.
 * The original CUBE remains on its source media; CRCs detect accidental
 * corruption, not malicious substitution or producer authenticity. */
int camera_lut_record_build(const struct camera_lut_record_meta *meta,
                            const void *source, size_t source_bytes,
                            const unsigned char *payload, size_t payload_bytes,
                            unsigned char *record, size_t capacity);
int camera_lut_record_validate(const unsigned char *record, size_t bytes);

/* directory must already be an application-owned directory. These are POSIX
 * file operations, never device mapping or camera settings APIs. Save uses
 * optimistic generation matching under a per-slot filesystem lock. Inputs
 * must be immutable during each call; save takes its own verified snapshot.
 * UNCERTAIN means primary was renamed but durability was not confirmed:
 * reconcile with load before any retry or device publication. */
int camera_lut_store_save(const char *directory, const unsigned char *record,
                          size_t bytes, uint64_t expected_generation,
                          struct camera_lut_store_result *result);
int camera_lut_store_load(const char *directory, uint32_t slot,
                          unsigned char *record, size_t capacity,
                          struct camera_lut_store_result *result);
#ifdef CAMERA_LUT_STORE_TESTING
/* Test builds only: numbered checkpoints or short writes/EINTR on host. */
void camera_lut_store_test_fault(int checkpoint);
void camera_lut_store_test_short_writes(int enabled);
#endif
#endif
