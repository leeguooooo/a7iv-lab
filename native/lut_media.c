#include "lut_media.h"
#include <string.h>
_Static_assert(sizeof(void *)==8,"Reviewed Fsys FILEINFO uses 64-bit pointers");

static int ap_first(void *p,const char *path,void *info) {
    return ((const struct camera_lut_fsys_functions *)p)->find_first(path,info);
}
static int ap_next(void *p,void *info) {
    return ((const struct camera_lut_fsys_functions *)p)->find_next(info);
}
static int ap_open(void *p,const char *path,uint64_t *handle) {
    return ((const struct camera_lut_fsys_functions *)p)->open(path,0,handle);
}
static int ap_read(void *p,uint64_t handle,void *buffer,size_t bytes,size_t *out) {
    return ((const struct camera_lut_fsys_functions *)p)->read(handle,buffer,bytes,out);
}
static int ap_close(void *p,uint64_t handle) {
    return ((const struct camera_lut_fsys_functions *)p)->close(handle);
}
int camera_lut_media_bind_wrappers(struct camera_lut_media_io *io,
                                  const struct camera_lut_fsys_functions *f) {
    if(!io||!f||!f->find_first||!f->find_next||!f->open||!f->read||!f->close)return CAMERA_LUT_MEDIA_INVALID;
    struct camera_lut_media_io value={(void *)f,ap_first,ap_next,ap_open,ap_read,ap_close};
    *io=value;return CAMERA_LUT_MEDIA_OK;
}

static int name_ok(const char *p,size_t n,int wildcard) {
    if(!p||!n||n>=CAMERA_LUT_MEDIA_NAME_BYTES)return 0;
    if(wildcard && n==3 && !memcmp(p,"*.*",3))return 1;
    for(size_t i=0;i<n;++i) {
        unsigned char c=(unsigned char)p[i];
        if(c<32||c==127||c=='/'||c=='\\'||c==':'||c=='*'||c=='?')return 0;
    }
    return !((n==1&&p[0]=='.')||(n==2&&p[0]=='.'&&p[1]=='.'));
}
static int cube_name(const char *name,size_t n) {
    return n>=5 && name[n-5]=='.' && (name[n-4]|32)=='c' &&
           (name[n-3]|32)=='u' && (name[n-2]|32)=='b' && (name[n-1]|32)=='e';
}
int camera_lut_media_path(const struct camera_lut_media_snapshot *snapshot,
                          uint32_t card,const char *name,size_t bytes,
                          char *path,size_t capacity) {
    if(!snapshot||card>1||!path||!name_ok(name,bytes,1))return CAMERA_LUT_MEDIA_INVALID;
    if(!snapshot->generation)return CAMERA_LUT_MEDIA_NOT_READY;
    const unsigned char *media=snapshot->media+card*0x70;
    uint32_t kind;memcpy(&kind,media+0x1c,4);
    unsigned char drive=media[0x19];
    if((kind!=3&&kind!=9)||drive<'A'||drive>'Z')return CAMERA_LUT_MEDIA_NOT_READY;
    const char *directory=kind==3 ? "/Private/Sony/PRO/LUT/" : "/Sony/PRO/LUT/";
    size_t directory_bytes=strlen(directory),total=2+directory_bytes+bytes+1;
    if(total>capacity)return CAMERA_LUT_MEDIA_CAPACITY_ERROR;
    path[0]=(char)drive;path[1]=':';memcpy(path+2,directory,directory_bytes);
    memcpy(path+2+directory_bytes,name,bytes);path[total-1]=0;
    return CAMERA_LUT_MEDIA_OK;
}
static int scan_failed(struct camera_lut_media_list *out,int status) {
    out->count=0;out->status=(uint32_t)status;return status;
}
int camera_lut_media_scan(const struct camera_lut_media_io *io,
                          const struct camera_lut_media_snapshot *snapshot,
                          uint32_t card,void *fileinfo,size_t fileinfo_bytes,
                          struct camera_lut_media_list *out) {
    if(!out)return CAMERA_LUT_MEDIA_INVALID;
    memset(out,0,sizeof(*out));out->card=card;
    if(!io||!io->find_first||!io->find_next||!snapshot||!fileinfo||fileinfo_bytes<CAMERA_LUT_MEDIA_FILEINFO_BYTES)return scan_failed(out,CAMERA_LUT_MEDIA_INVALID);
    out->media_generation=snapshot->generation;
    char path[CAMERA_LUT_MEDIA_PATH_BYTES];
    int status=camera_lut_media_path(snapshot,card,"*.*",3,path,sizeof(path));
    if(status)return scan_failed(out,status);
    memset(fileinfo,0,CAMERA_LUT_MEDIA_FILEINFO_BYTES);
    status=io->find_first(io->context,path,fileinfo);
    uint32_t visited=0;
    while(status==0) {
        if(++visited>4096)return scan_failed(out,CAMERA_LUT_MEDIA_LIMIT);
        if(((unsigned char *)fileinfo)[0x26]&0x10){status=io->find_next(io->context,fileinfo);continue;}
        const char *name;uint64_t bytes;
        memcpy(&name,fileinfo,8);memcpy(&bytes,(unsigned char *)fileinfo+8,8);
        uintptr_t start=(uintptr_t)fileinfo,ptr=(uintptr_t)name;
        if(ptr<start||ptr-start>=CAMERA_LUT_MEDIA_FILEINFO_BYTES)return scan_failed(out,CAMERA_LUT_MEDIA_CORRUPT);
        size_t remaining=CAMERA_LUT_MEDIA_FILEINFO_BYTES-(size_t)(ptr-start),n=0;
        while(n<remaining && n<CAMERA_LUT_MEDIA_NAME_BYTES && name[n])++n;
        if(n==remaining||n==CAMERA_LUT_MEDIA_NAME_BYTES)return scan_failed(out,CAMERA_LUT_MEDIA_CORRUPT);
        if(!name_ok(name,n,0))return scan_failed(out,CAMERA_LUT_MEDIA_CORRUPT);
        if(cube_name(name,n)) {
            if(out->count==CAMERA_LUT_MEDIA_CAPACITY)return scan_failed(out,CAMERA_LUT_MEDIA_LIMIT);
            struct camera_lut_media_entry *entry=out->entries+out->count++;
            memcpy(entry->name,name,n);entry->name_bytes=(uint32_t)n;entry->file_bytes=bytes;
            entry->status=(!bytes||bytes>CAMERA_CUBE_MAX_BYTES) ? CAMERA_LUT_MEDIA_LIMIT : CAMERA_LUT_MEDIA_OK;
        }
        status=io->find_next(io->context,fileinfo);
    }
    if(status!=4)return scan_failed(out,CAMERA_LUT_MEDIA_IO);
    return CAMERA_LUT_MEDIA_OK;
}
int camera_lut_media_read(const struct camera_lut_media_io *io,
                          const struct camera_lut_media_snapshot *snapshot,
                          uint32_t card,const struct camera_lut_media_entry *entry,
                          uint64_t selected_generation,unsigned char *temporary,
                          size_t capacity,size_t *bytes_out) {
    if(!io||!io->open_read||!io->read||!io->close||!snapshot||!entry||!temporary||!bytes_out)return CAMERA_LUT_MEDIA_INVALID;
    if(!selected_generation||selected_generation!=snapshot->generation)return CAMERA_LUT_MEDIA_STALE;
    size_t name_bytes=entry->name_bytes;
    if(name_bytes>=sizeof(entry->name)||entry->name[name_bytes]||!name_ok(entry->name,name_bytes,0)||!cube_name(entry->name,name_bytes))return CAMERA_LUT_MEDIA_INVALID;
    if(entry->status||!entry->file_bytes||entry->file_bytes>CAMERA_CUBE_MAX_BYTES)return CAMERA_LUT_MEDIA_LIMIT;
    if(capacity<=entry->file_bytes)return CAMERA_LUT_MEDIA_CAPACITY_ERROR;
    char path[CAMERA_LUT_MEDIA_PATH_BYTES];int status=camera_lut_media_path(snapshot,card,entry->name,name_bytes,path,sizeof(path));
    if(status)return status;
    uint64_t handle=0;size_t at=0,limit=(size_t)entry->file_bytes+1;
    if(io->open_read(io->context,path,&handle)!=0)return CAMERA_LUT_MEDIA_IO;
    for(;;) {
        size_t count=0,amount=limit-at;
        if(io->read(io->context,handle,temporary+at,amount,&count)!=0||count>amount){status=CAMERA_LUT_MEDIA_IO;break;}
        at+=count;
        if(at>entry->file_bytes){status=CAMERA_LUT_MEDIA_STALE;break;}
        if(!count){status=at==entry->file_bytes ? CAMERA_LUT_MEDIA_OK : CAMERA_LUT_MEDIA_STALE;break;}
    }
    if(io->close(io->context,handle)!=0)status=CAMERA_LUT_MEDIA_IO;
    if(!status)*bytes_out=at;
    return status;
}
