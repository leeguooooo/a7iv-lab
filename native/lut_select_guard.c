#include "lut_select_guard.h"
#include <string.h>
_Static_assert(sizeof(uintptr_t)==8,"reviewed AP object uses64-bit pointers");
_Static_assert(sizeof(struct camera_lut_select_functions)==16,"AP callback table layout");
_Static_assert(sizeof(struct camera_lut_select_result)==24,"select result layout");
_Static_assert(offsetof(struct camera_lut_select_result,config_return)==20,"select result return field");

static int overlap(const void *a,size_t an,const void *b,size_t bn) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y ? y-x<an : x-y<bn;
}
int camera_lut_ap_select_checked(const void *object,size_t bytes,
                                 uintptr_t expected_vtable,
                                 const struct camera_lut_select_functions *functions,
                                 struct camera_lut_select_result *out) {
    if(!object||!functions||!out||!expected_vtable||bytes<CAMERA_LUT_AP_SELECT_OBJECT_BYTES)
        return CAMERA_LUT_SELECT_INVALID;
    if(overlap(object,CAMERA_LUT_AP_SELECT_OBJECT_BYTES,out,sizeof(*out))||
       overlap(functions,sizeof(*functions),out,sizeof(*out)))return CAMERA_LUT_SELECT_INVALID;
    struct camera_lut_select_functions calls=*functions;
    if(!calls.send_lut||!calls.request_config)return CAMERA_LUT_SELECT_INVALID;
    unsigned char captured[CAMERA_LUT_AP_SELECT_OBJECT_BYTES];
    memcpy(captured,object,sizeof(captured));
    uintptr_t vtable;uint32_t first,selected,exists;
    memcpy(&vtable,captured,sizeof(vtable));
    memcpy(&first,captured+0x14,4);memcpy(&selected,captured+0x18,4);
    memcpy(&exists,captured+0x6c,4);
    if(vtable!=expected_vtable)return CAMERA_LUT_SELECT_WRONG_TYPE;
    if(selected>18||exists>1)return CAMERA_LUT_SELECT_INVALID;
    if(selected>=3&&!exists)return CAMERA_LUT_SELECT_UNAVAILABLE;
    struct camera_lut_select_result result={0};result.selected=selected;
    result.send_return=calls.send_lut(selected,exists,&result.handle,&result.bytes);
    if(result.send_return!=1) {
        *out=result;return CAMERA_LUT_SELECT_PREPARE_FAILED;
    }
    if(selected>=3&&(!result.handle||!result.bytes)) {
        *out=result;return CAMERA_LUT_SELECT_EMPTY_TRANSFER;
    }
    result.config_called=1;
    result.config_return=calls.request_config(first,selected,result.handle,result.bytes,captured+0x2c);
    *out=result;
    return result.config_return==1 ? CAMERA_LUT_SELECT_CONFIG_REQUESTED : CAMERA_LUT_SELECT_CONFIG_UNCONFIRMED;
}
