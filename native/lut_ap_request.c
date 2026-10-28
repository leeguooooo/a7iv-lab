#include "lut_ap_request.h"
#include <string.h>

int camera_lut_ap_capture_local_copy(const void *object,size_t bytes,
                                     uintptr_t expected_vtable,
                                     uint64_t selected_generation,
                                     uint64_t current_generation,
                                     uint64_t request_id,
                                     struct camera_lut_import_request *out) {
    if(!object||!out||bytes<CAMERA_LUT_AP_LOCAL_COPY_BYTES||!expected_vtable||!request_id)return CAMERA_LUT_MEDIA_INVALID;
    if(!selected_generation||!current_generation)return CAMERA_LUT_MEDIA_NOT_READY;
    if(selected_generation!=current_generation)return CAMERA_LUT_MEDIA_STALE;
    uintptr_t source=(uintptr_t)object,dest=(uintptr_t)out;
    if(source<=dest ? dest-source<CAMERA_LUT_AP_LOCAL_COPY_BYTES : source-dest<sizeof(*out))return CAMERA_LUT_MEDIA_INVALID;
    unsigned char captured[CAMERA_LUT_AP_LOCAL_COPY_BYTES];
    memcpy(captured,object,sizeof(captured));
    uintptr_t vtable;memcpy(&vtable,captured,sizeof(vtable));
    if(vtable!=expected_vtable)return CAMERA_LUT_MEDIA_CORRUPT;
    uint32_t card,selected;memcpy(&card,captured+0x18,4);memcpy(&selected,captured+0x1ac,4);
    if(card>1||selected<3||selected>18)return CAMERA_LUT_MEDIA_INVALID;
    size_t n=0;while(n<64&&captured[0x16c+n])++n;
    if(n<5||n==64||captured[0x16c+n-5]!='.'||
       (captured[0x16c+n-4]|32)!='c'||(captured[0x16c+n-3]|32)!='u'||
       (captured[0x16c+n-2]|32)!='b'||(captured[0x16c+n-1]|32)!='e')return CAMERA_LUT_MEDIA_INVALID;
    struct camera_lut_import_request request={0};
    request.request_id=request_id;request.snapshot.generation=current_generation;
    /* Do not retain opaque bytes from a native object: only the drive/kind
     * fields used by our media adapter have a reviewed value contract. */
    for(unsigned index=0;index<2;++index) {
        size_t base=index*0x70;
        request.snapshot.media[base+0x19]=captured[0x1c+base+0x19];
        memcpy(request.snapshot.media+base+0x1c,captured+0x1c+base+0x1c,4);
    }
    request.card=card;request.slot=selected-3;request.filename_bytes=(uint32_t)n;
    memcpy(request.filename,captured+0x16c,n);
    char path[CAMERA_LUT_MEDIA_PATH_BYTES];
    int status=camera_lut_media_path(&request.snapshot,card,request.filename,n,path,sizeof(path));
    if(status)return status;
    *out=request;
    return CAMERA_LUT_MEDIA_OK;
}
