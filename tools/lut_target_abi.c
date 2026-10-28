/* Compile-time data only. This object has no executable entry point. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include "../native/cube_input.h"
#include "../native/lut_store.h"
#ifdef CAMERA_LUT_MEDIA_ABI
#include "../native/lut_media.h"
#endif
#ifdef CAMERA_LUT_AP_REQUEST_ABI
#include "../native/lut_ap_request.h"
#endif
#ifdef CAMERA_LUT_SELECT_GUARD_ABI
#include "../native/lut_select_guard.h"
#endif

const uint64_t camera_lut_target_abi_values[] = {
    sizeof(size_t), sizeof(off_t), sizeof(struct stat),
    offsetof(struct stat,st_mode), offsetof(struct stat,st_size),
    sizeof(struct camera_cube_info), offsetof(struct camera_cube_info,explicit_domain),
    sizeof(struct camera_lut_record_meta), offsetof(struct camera_lut_record_meta,generation),
    offsetof(struct camera_lut_record_meta,filename),
    sizeof(struct camera_lut_store_result), offsetof(struct camera_lut_store_result,from_backup),
    O_RDONLY,O_RDWR,O_CREAT,O_EXCL,O_DIRECTORY,O_NOFOLLOW,
    LOCK_SH,LOCK_EX,LOCK_NB,CAMERA_LUT_RECORD_BYTES
#ifdef CAMERA_LUT_MEDIA_ABI
    ,sizeof(struct camera_lut_media_snapshot),offsetof(struct camera_lut_media_snapshot,generation)
    ,sizeof(struct camera_lut_media_entry),offsetof(struct camera_lut_media_entry,name)
    ,sizeof(struct camera_lut_media_list),offsetof(struct camera_lut_media_list,entries)
    ,sizeof(struct camera_lut_media_io),offsetof(struct camera_lut_media_io,open_read)
    ,sizeof(struct camera_lut_fsys_functions)
#endif
#ifdef CAMERA_LUT_AP_REQUEST_ABI
    ,sizeof(struct camera_lut_import_request),offsetof(struct camera_lut_import_request,snapshot)
    ,offsetof(struct camera_lut_import_request,card),offsetof(struct camera_lut_import_request,filename)
#endif
#ifdef CAMERA_LUT_SELECT_GUARD_ABI
    ,sizeof(struct camera_lut_select_functions),offsetof(struct camera_lut_select_functions,request_config)
    ,sizeof(struct camera_lut_select_result),offsetof(struct camera_lut_select_result,config_called)
    ,offsetof(struct camera_lut_select_result,config_return)
#endif
};
