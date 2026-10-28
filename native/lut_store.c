#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#include "lut_store.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static const unsigned char magic[8]={'A','7','L','U','T','0','1',0};
static uint32_t u32(const unsigned char *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint64_t u64(const unsigned char *p) { return u32(p)|(uint64_t)u32(p+4)<<32; }
static void put32(unsigned char *p,uint32_t v) { for(unsigned i=0;i<4;++i)p[i]=(unsigned char)(v>>(8*i)); }
static void put64(unsigned char *p,uint64_t v) { put32(p,(uint32_t)v);put32(p+4,(uint32_t)(v>>32)); }
static uint32_t crc(const unsigned char *p,size_t n,int record) {
    uint32_t c=~0u;
    for(size_t i=0;i<n;++i) {
        c^=record && i>=252 && i<256 ? 0 : p[i];
        for(unsigned k=0;k<8;++k)c=(c>>1)^(0xedb88320u & (0u-(c&1u)));
    }
    return ~c;
}
static int text_ok(const unsigned char *p,size_t n,int filename) {
    size_t used=0;
    while(used<n && p[used]) {
        unsigned char c=p[used++];
        if(c<32 || c==127 || (filename && (c=='/' || c=='\\')))return 0;
        if(c>=128) {
            unsigned more,point;
            if(c>=0xc2 && c<=0xdf){more=1;point=c&31;}
            else if(c>=0xe0 && c<=0xef){more=2;point=c&15;}
            else if(c>=0xf0 && c<=0xf4){more=3;point=c&7;}
            else return 0;
            unsigned count=more;
            while(more--) {
                if(used>=n || (p[used]&0xc0)!=0x80)return 0;
                point=(point<<6)|(p[used++]&63);
            }
            if((count==2 && point<0x800)||(count==3 && point<0x10000)||point>0x10ffff||(point>=0xd800 && point<=0xdfff))return 0;
        }
    }
    if(!used || used==n)return 0;
    for(size_t i=used;i<n;++i)if(p[i])return 0;
    if(filename && ((used==1 && p[0]=='.')||(used==2 && p[0]=='.' && p[1]=='.')))return 0;
    return 1;
}
static int copy_text(unsigned char *out,size_t n,const char *s,int filename) {
    if(!s)return 0;
    size_t len=strnlen(s,n);
    if(!len || len>=n)return 0;
    memcpy(out,s,len);return text_ok(out,n,filename);
}
int camera_lut_record_validate(const unsigned char *p,size_t n) {
    if(!p || n!=CAMERA_LUT_RECORD_BYTES || memcmp(p,magic,8) || u32(p+8)!=1 || u32(p+12)!=256 || u32(p+16)!=n || u32(p+20)>=16 || !u64(p+24))return CAMERA_LUT_STORE_INVALID;
    unsigned source=u32(p+40),target=u32(p+44);
    if(!u32(p+36)||u32(p+36)>CAMERA_CUBE_MAX_BYTES || source<2||source>65 || (target!=17 && target!=33)||u32(p+48)!=1||u32(p+52)!=48000||u32(p+56)>1||u32(p+60)>1)return CAMERA_LUT_STORE_INVALID;
    if(u32(p+64)>target*target*target || u32(p+68)>17u*17u*17u*3u || (!u32(p+56)&&u32(p+64)) || (!u32(p+60)&&u32(p+68)))return CAMERA_LUT_STORE_INVALID;
    if(!text_ok(p+72,64,1)||!text_ok(p+136,48,0)||!text_ok(p+184,48,0))return CAMERA_LUT_STORE_INVALID;
    for(unsigned i=232;i<252;++i)if(p[i])return CAMERA_LUT_STORE_INVALID;
    return crc(p,n,1)==u32(p+252) ? CAMERA_LUT_STORE_OK : CAMERA_LUT_STORE_CORRUPT;
}
int camera_lut_record_build(const struct camera_lut_record_meta *m,const void *source,size_t source_bytes,const unsigned char *payload,size_t payload_bytes,unsigned char *out,size_t capacity) {
    if(!m||!source||!source_bytes||source_bytes>CAMERA_CUBE_MAX_BYTES||!payload||payload_bytes!=48000||!out||capacity<CAMERA_LUT_RECORD_BYTES)return CAMERA_LUT_STORE_INVALID;
    unsigned char header[256]={0};memcpy(header,magic,8);
    put32(header+8,1);put32(header+12,256);put32(header+16,CAMERA_LUT_RECORD_BYTES);put32(header+20,m->slot);put64(header+24,m->generation);
    put32(header+32,crc(source,source_bytes,0));put32(header+36,(uint32_t)source_bytes);put32(header+40,m->source_grid);put32(header+44,m->compiled_grid);put32(header+48,1);put32(header+52,48000);
    put32(header+56,m->bounds_policy);put32(header+60,m->quantization_policy);put32(header+64,m->clamped_nodes);put32(header+68,m->saturated_components);
    if(!copy_text(header+72,64,m->filename,1)||!copy_text(header+136,48,m->input_space,0)||!copy_text(header+184,48,m->output_space,0))return CAMERA_LUT_STORE_INVALID;
    if(m->slot>=16||!m->generation||m->source_grid<2||m->source_grid>65||(m->compiled_grid!=17&&m->compiled_grid!=33)||m->bounds_policy>1||m->quantization_policy>1)return CAMERA_LUT_STORE_INVALID;
    if(m->clamped_nodes>m->compiled_grid*m->compiled_grid*m->compiled_grid || m->saturated_components>17u*17u*17u*3u || (!m->bounds_policy&&m->clamped_nodes) || (!m->quantization_policy&&m->saturated_components))return CAMERA_LUT_STORE_INVALID;
    /* Output may share the payload's underlying allocation. */
    memmove(out+256,payload,48000);memcpy(out,header,256);put32(out+252,crc(out,CAMERA_LUT_RECORD_BYTES,1));return CAMERA_LUT_STORE_OK;
}

#ifdef CAMERA_LUT_STORE_TESTING
static int fault,short_writes,interrupt_write;
void camera_lut_store_test_fault(int point){fault=point;}
void camera_lut_store_test_short_writes(int enabled){short_writes=enabled;interrupt_write=enabled;}
static int checkpoint(int point){if(fault==point){errno=EIO;return -1;}return 0;}
#else
static int checkpoint(int point){(void)point;return 0;}
#endif
static int write_all(int fd,const unsigned char *p,size_t n) {
    while(n) {
        size_t amount=n;
#ifdef CAMERA_LUT_STORE_TESTING
        if(interrupt_write){interrupt_write=0;errno=EINTR;continue;}
        if(short_writes && amount>17)amount=17;
#endif
        ssize_t done=write(fd,p,amount);
        if(done<0 && errno==EINTR)continue;
        if(done<=0)return -1;
        p+=done;n-=(size_t)done;
    }
    return 0;
}
static int read_record(int dir,const char *name,unsigned char *p,unsigned slot) {
    int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW);
    if(fd<0)return errno==ENOENT ? CAMERA_LUT_STORE_NOT_FOUND : CAMERA_LUT_STORE_IO;
    struct stat st;int status=CAMERA_LUT_STORE_IO;
    if(fstat(fd,&st)<0 || !S_ISREG(st.st_mode))goto end;
    if(st.st_size!=CAMERA_LUT_RECORD_BYTES){status=CAMERA_LUT_STORE_CORRUPT;goto end;}
    size_t at=0;
    while(at<CAMERA_LUT_RECORD_BYTES) {
        ssize_t n=read(fd,p+at,CAMERA_LUT_RECORD_BYTES-at);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)goto end;
        at+=(size_t)n;
    }
    status=camera_lut_record_validate(p,CAMERA_LUT_RECORD_BYTES);
    if(!status && u32(p+20)!=slot)status=CAMERA_LUT_STORE_CORRUPT;
end:
    if(close(fd)<0)status=CAMERA_LUT_STORE_IO;
    return status;
}
static int lock_slot(int dir,unsigned slot,int write_lock) {
    char name[32];snprintf(name,sizeof(name),"slot%02u.lock",slot);
    int fd=openat(dir,name,O_CREAT|O_RDWR|O_NOFOLLOW,0600);
    if(fd<0)return -1;
    struct stat st;
    if(fstat(fd,&st)<0 || !S_ISREG(st.st_mode)){close(fd);errno=EINVAL;return -1;}
    if(flock(fd,(write_lock?LOCK_EX:LOCK_SH)|LOCK_NB)<0){int e=errno;close(fd);errno=e;return -1;}
    return fd;
}
static int stage(int dir,unsigned slot,uint64_t generation,const char *kind,const unsigned char *p,char name[80]) {
    int fd=-1;char candidate[80];name[0]=0;
    for(unsigned attempt=0;attempt<64;++attempt) {
        snprintf(candidate,sizeof(candidate),".slot%02u.%s.%llu.%u",slot,kind,(unsigned long long)generation,attempt);
        fd=openat(dir,candidate,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);
        if(fd>=0){memcpy(name,candidate,strlen(candidate)+1);break;}
        if(errno!=EEXIST)return -1;
    }
    if(fd<0)return -1;
    int ok=write_all(fd,p,CAMERA_LUT_RECORD_BYTES)==0 && checkpoint(1)==0 && fsync(fd)==0;
    if(close(fd)<0)ok=0;
    if(!ok){unlinkat(dir,name,0);return -1;}
    return 0;
}
int camera_lut_store_load(const char *directory,uint32_t slot,unsigned char *record,size_t capacity,struct camera_lut_store_result *result) {
    if(!directory||slot>=16||!record||capacity<CAMERA_LUT_RECORD_BYTES||!result)return CAMERA_LUT_STORE_INVALID;
    int dir=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(dir<0)return CAMERA_LUT_STORE_IO;
    int lock=lock_slot(dir,slot,0),status=CAMERA_LUT_STORE_IO;
    unsigned char *tmp=0;unsigned backup=0;char name[32];
    if(lock<0){status=(errno==EWOULDBLOCK||errno==EAGAIN)?CAMERA_LUT_STORE_BUSY:CAMERA_LUT_STORE_IO;goto end;}
    tmp=malloc(CAMERA_LUT_RECORD_BYTES);if(!tmp)goto end;
    snprintf(name,sizeof(name),"slot%02u.lut",slot);status=read_record(dir,name,tmp,slot);
    if(status==CAMERA_LUT_STORE_NOT_FOUND||status==CAMERA_LUT_STORE_CORRUPT||status==CAMERA_LUT_STORE_INVALID) {
        int primary=status;snprintf(name,sizeof(name),"slot%02u.bak",slot);status=read_record(dir,name,tmp,slot);backup=1;
        if(status==CAMERA_LUT_STORE_NOT_FOUND && primary!=CAMERA_LUT_STORE_NOT_FOUND)status=primary;
    }
    if(!status){struct camera_lut_store_result r={u64(tmp+24),backup,0,0};memcpy(record,tmp,CAMERA_LUT_RECORD_BYTES);*result=r;}
end:
    free(tmp);if(lock>=0)close(lock);close(dir);return status;
}
int camera_lut_store_save(const char *directory,const unsigned char *record,size_t bytes,uint64_t expected,struct camera_lut_store_result *result) {
    if(!directory||!record||!result||bytes!=CAMERA_LUT_RECORD_BYTES)return CAMERA_LUT_STORE_INVALID;
    unsigned char *snapshot=malloc(bytes);
    if(!snapshot)return CAMERA_LUT_STORE_IO;
    memcpy(snapshot,record,bytes);
    if(camera_lut_record_validate(snapshot,bytes)){free(snapshot);return CAMERA_LUT_STORE_INVALID;}
    if(expected==UINT64_MAX || u64(snapshot+24)!=expected+1){free(snapshot);return CAMERA_LUT_STORE_CONFLICT;}
    unsigned slot=u32(snapshot+20);int dir=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(dir<0){free(snapshot);return CAMERA_LUT_STORE_IO;}
    int lock=lock_slot(dir,slot,1),status=CAMERA_LUT_STORE_IO;unsigned char *previous=0;
    char primary[32],backup[32],temporary[80]={0};struct camera_lut_store_result state={0};
    if(lock<0){status=(errno==EWOULDBLOCK||errno==EAGAIN)?CAMERA_LUT_STORE_BUSY:CAMERA_LUT_STORE_IO;goto end;}
    previous=malloc(CAMERA_LUT_RECORD_BYTES);if(!previous)goto end;
    snprintf(primary,sizeof(primary),"slot%02u.lut",slot);snprintf(backup,sizeof(backup),"slot%02u.bak",slot);
    int old=read_record(dir,primary,previous,slot),from_backup=0;
    if(old==CAMERA_LUT_STORE_NOT_FOUND||old==CAMERA_LUT_STORE_CORRUPT||old==CAMERA_LUT_STORE_INVALID) {
        int first=old;old=read_record(dir,backup,previous,slot);from_backup=1;
        if(old==CAMERA_LUT_STORE_NOT_FOUND && first!=CAMERA_LUT_STORE_NOT_FOUND){status=first;goto end;}
    }
    if(old!=CAMERA_LUT_STORE_OK && old!=CAMERA_LUT_STORE_NOT_FOUND){status=old;goto end;}
    uint64_t current=old==CAMERA_LUT_STORE_OK ? u64(previous+24) : 0;
    if(current!=expected){status=CAMERA_LUT_STORE_CONFLICT;goto end;}
    state.from_backup=(uint32_t)(from_backup && !old);
    if(!old && !from_backup) {
        if(stage(dir,slot,current,"backup",previous,temporary)<0)goto end;
        if(checkpoint(2)<0 || renameat(dir,temporary,dir,backup)<0)goto end;
        temporary[0]=0;if(fsync(dir)<0)goto end;
    }
    if(stage(dir,slot,expected+1,"new",snapshot,temporary)<0)goto end;
    if(checkpoint(3)<0 || renameat(dir,temporary,dir,primary)<0)goto end;
    temporary[0]=0;state.renamed_primary=1;state.generation=expected+1;
    if(checkpoint(4)<0 || fsync(dir)<0){status=CAMERA_LUT_STORE_UNCERTAIN;goto end;}
    state.directory_synced=1;status=CAMERA_LUT_STORE_OK;
end:
    if(temporary[0])unlinkat(dir,temporary,0);
    if(lock>=0){close(lock);*result=state;}
    free(previous);free(snapshot);close(dir);return status;
}
