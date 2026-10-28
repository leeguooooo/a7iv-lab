#ifndef CAMERA_LUT_MEDIA_H
#define CAMERA_LUT_MEDIA_H
#include <stddef.h>
#include <stdint.h>
#include "cube_input.h"

#define CAMERA_LUT_MEDIA_BYTES 224u
#define CAMERA_LUT_MEDIA_NAME_BYTES 256u
#define CAMERA_LUT_MEDIA_CAPACITY 64u
#define CAMERA_LUT_MEDIA_FILEINFO_BYTES 4096u
#define CAMERA_LUT_MEDIA_PATH_BYTES 512u

enum camera_lut_media_status {
    CAMERA_LUT_MEDIA_OK=0,CAMERA_LUT_MEDIA_INVALID,CAMERA_LUT_MEDIA_NOT_READY,
    CAMERA_LUT_MEDIA_IO,CAMERA_LUT_MEDIA_LIMIT,CAMERA_LUT_MEDIA_CORRUPT,
    CAMERA_LUT_MEDIA_STALE,CAMERA_LUT_MEDIA_CAPACITY_ERROR
};
struct camera_lut_media_snapshot {
    /* Only drive(+0x19) and kind(+0x1c) of each0x70 stride are interpreted.
     * Other bytes are reserved; this is not an SDK object to pass elsewhere. */
    unsigned char media[CAMERA_LUT_MEDIA_BYTES];
    /* Must come from the frontend's actual media-change lifecycle, not a
     * guessed field in media[]. Zero is unbound and rejected. */
    uint64_t generation;
};
struct camera_lut_media_entry {
    uint32_t name_bytes,status;
    uint64_t file_bytes;
    char name[CAMERA_LUT_MEDIA_NAME_BYTES];
};
struct camera_lut_media_list {
    uint64_t media_generation;
    uint32_t card,count,status,reserved;
    struct camera_lut_media_entry entries[CAMERA_LUT_MEDIA_CAPACITY];
};
/* Normalized original-wrapper ABI: find returns0 for entry,4 for end;
 * open/read/close return0 for success. This module never supplies write APIs.
 * FILEINFO belongs to this call and must be at least4096 bytes. */
struct camera_lut_media_io {
    void *context;
    int (*find_first)(void *,const char *,void *);
    int (*find_next)(void *,void *);
    int (*open_read)(void *,const char *,uint64_t *);
    int (*read)(void *,uint64_t,void *,size_t,size_t *);
    int (*close)(void *,uint64_t);
};
/* Pointer ABI glue for the reviewed original AP wrappers. The AP loader must
 * first establish exact source identity, load bias and instruction guards.
 * Supplying nonnull pointers here does NOT establish those facts. The table
 * must remain immutable/alive until all associated worker calls complete. */
struct camera_lut_fsys_functions {
    int (*find_first)(const char *,void *);
    int (*find_next)(void *);
    int (*open)(const char *,uint32_t,uint64_t *);
    int (*read)(uint64_t,void *,size_t,size_t *);
    int (*close)(uint64_t);
};
int camera_lut_media_bind_wrappers(struct camera_lut_media_io *io,
                                  const struct camera_lut_fsys_functions *functions);
int camera_lut_media_path(const struct camera_lut_media_snapshot *snapshot,
                          uint32_t card,const char *name,size_t name_bytes,
                          char *path,size_t capacity);
int camera_lut_media_scan(const struct camera_lut_media_io *io,
                          const struct camera_lut_media_snapshot *snapshot,
                          uint32_t card,void *fileinfo,size_t fileinfo_bytes,
                          struct camera_lut_media_list *result);
/* Only bytes_out is committed on success; temporary may change on failure.
 * Requires expected size+1 capacity to detect a file that grew. The frontend
 * must recheck actual media generation before publishing the queued result. */
int camera_lut_media_read(const struct camera_lut_media_io *io,
                          const struct camera_lut_media_snapshot *snapshot,
                          uint32_t card,const struct camera_lut_media_entry *entry,
                          uint64_t selected_generation,unsigned char *temporary,
                          size_t capacity,size_t *bytes_out);
#endif
