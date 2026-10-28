#ifndef CAMERA_LUT_AP_REQUEST_H
#define CAMERA_LUT_AP_REQUEST_H
#include "lut_media.h"

#define CAMERA_LUT_AP_LOCAL_COPY_BYTES 704u
struct camera_lut_import_request {
    uint64_t request_id;
    struct camera_lut_media_snapshot snapshot;
    uint32_t card,slot,filename_bytes,reserved;
    char filename[64];
};

/* Capture only the reviewed local sequence_cube_file_copy layout. The caller
 * must hold a live immutable object and establish exact AP source/load-bias/
 * vtable instruction guards beforehand. A matching supplied vptr is NOT proof
 * of those facts. Only reviewed drive/kind fields are copied from media[];
 * every opaque/reserved byte is zero. No source-object pointers survive.
 *
 * Both generations must come from the actual frontend lifecycle. Zero is
 * unbound; equality is checked before object access. request_id is a nonzero
 * frontend correlation/cancellation token, not an invented camera epoch.
 * result is owned by the caller and stays unchanged on failure. No IO/queue/
 * GUI hook/store/CP mutation occurs here. */
int camera_lut_ap_capture_local_copy(const void *object,size_t object_bytes,
                                     uintptr_t verified_runtime_vtable,
                                     uint64_t selection_generation,
                                     uint64_t current_generation,
                                     uint64_t request_id,
                                     struct camera_lut_import_request *result);
#endif
