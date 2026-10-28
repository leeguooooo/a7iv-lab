#ifndef CAMERA_LUT_SELECT_GUARD_H
#define CAMERA_LUT_SELECT_GUARD_H
#include <stddef.h>
#include <stdint.h>
#define CAMERA_LUT_AP_SELECT_OBJECT_BYTES 112u

enum camera_lut_select_status {
    /* The original config helper returned1. This is NOT CP acknowledgement,
     * image activation or a durable commit. */
    CAMERA_LUT_SELECT_CONFIG_REQUESTED=0,
    CAMERA_LUT_SELECT_INVALID,
    CAMERA_LUT_SELECT_WRONG_TYPE,
    CAMERA_LUT_SELECT_UNAVAILABLE,
    CAMERA_LUT_SELECT_PREPARE_FAILED,
    CAMERA_LUT_SELECT_EMPTY_TRANSFER,
    CAMERA_LUT_SELECT_CONFIG_UNCONFIRMED
};
struct camera_lut_select_functions {
    /* Reviewed original send_lut 3503930 and config3503b44 ABI. A loader must
     * establish the exact AP identity/load bias/code guards, owning sequence
     * lifecycle and serialization first. Nonnull callbacks do not prove it. */
    int (*send_lut)(uint32_t selected,uint32_t exists,
                    uint32_t *handle,uint32_t *bytes);
    int (*request_config)(uint32_t first_config,uint32_t selected,
                          uint32_t handle,uint32_t bytes,
                          const unsigned char metadata[64]);
};
struct camera_lut_select_result {
    uint32_t selected,handle,bytes,config_called;
    int32_t send_return,config_return;
};
/* Synchronous checked adapter for ONLY model::sequence_select_lut's112B
 * reviewed layout, not the704B local-copy class. Caller holds the object
 * immutable/alive, including media/slot-generation validity and actor locks.
 * Calls snapshot function pointers and value fields before invoking anything.
 * Config metadata is borrowed only for that synchronous call; callback must
 * copy it and retain no pointer. This does not discover/bind/install an AP
 * hook, create a queue, or establish real CP acknowledgement.
 *
 * Validation rejection leaves result unchanged and invokes no callback.
 * Once send_lut is invoked, result records outcomes even on failure. User
 * selections3..18 require exists==1 and nonzero handle/length after send.
 * Builtins0..2 preserve the native zero-handle config path. Send/config must
 * return exactly1 for their known native success return. No retries/rollback.
 */
int camera_lut_ap_select_checked(const void *object,size_t object_bytes,
                                 uintptr_t verified_runtime_vtable,
                                 const struct camera_lut_select_functions *functions,
                                 struct camera_lut_select_result *result);
#endif
