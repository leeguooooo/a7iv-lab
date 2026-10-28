/* Candidate: single-partition chunked READ-ONLY backup worker (pilot = cnflasha7).
 *
 * STATUS: offline candidate; see exact-artifact build/emulation manifests.
 * No hardware acceptance or bootstrap/executor. New file only — the
 * existing <=32 MiB backup.c is unchanged. NO block write, NO mount/freeze, NO
 * kernel/DMA/NOR/CSPI. Source is opened O_RDONLY; wrong device identity => refuse.
 *
 * Reuses the proven lifecycle + linux_a64 helpers exactly as backup.c does, and
 * the identity-gate + two-pass(first==second) discipline of backup.c::capture().
 *
 * Wire format — matches camera_stream_receiver.py exactly:
 *   RECORD 80 B  <8s magic, 16s nonce, u64 index, u64 offset, u64 length, 32s sha256>
 *     chunk magic "M4CHNK01"; final magic "M4DONE01" reuses the same 80 B record as
 *     {magic, nonce, chunks(->index), size(->offset), error(->length), sha256(->digest)}.
 *   ACK   64 B  <8s "M4SACK01", 16s nonce, u64 index, 32s sha256>  (host -> worker)
 * Files in JOB_DIR (tmpfs): publish payload "chunk.bin", then 80B "chunk.ready"
 *   via renameat2(RENAME_NOREPLACE) from owned "chunk.tmp". Host writes "ack";
 *   validated ACK is removed, then our payload/record are removed before next.
 *   Final 80B "done" remains. The lifecycle "ready" is a separate record.
 */
#define _start unused_lifecycle_start
#define worker_main unused_lifecycle_main
#define result lifecycle_result
#include "lifecycle_worker.c"
#undef result
#undef worker_main
#undef _start
#include "sha256.h"

/* --- fixed pilot identity (historical evidence: proc_partitions "252 135 16384
 * cnflasha7"; mountinfo "252:135 ... ext2"). Mismatch at runtime => refuse. --- */
#ifdef STREAM_TEST_IMAGE   /* tiny VM only; compile-time constant; same source SHA */
  #define PART_SIZE   8192UL
  #define SECTORS_STR "16\n"
  #define CHUNK       4096UL
#else                       /* production */
  #define PART_SIZE   16777216UL
  #define SECTORS_STR "32768\n"
  #define CHUNK       8388608UL
#endif
#define PART_PATH   "/dev/cnflasha7"
#define PART_RDEV   64647UL            /* (252<<8)|135 */
#define SYS_DEV     "/sys/class/block/cnflasha7/dev"
#define DEV_STR     "252:135\n"
#define SYS_SIZE    "/sys/class/block/cnflasha7/size"
#define READ_STEP   65536UL            /* <=64 KiB per pread call */
#define ACK_TIMEOUT 300                /* seconds */

struct StreamResult {
    u8 magic[8], nonce[16];
    i64 version, phase, error, euid, pid, ppid, loader_pid, cleanup,
        index, offset, chunks, flags;
    u8 first[32], second[32];
};
_Static_assert(sizeof(struct StreamResult)==184,"stream result ABI");
static struct StreamResult sr;
static u8 chunk[CHUNK];            /* single worker buffer (<=8 MiB) */
static u8 ackbuf[65], idbuf[64], st[128];
static i64 source=-1;
static int own_tmp,own_data,own_record;

static i64 renameat2_noreplace(const char*oldp,const char*newp) {
    return sc(276,-100,(i64)oldp,-100,(i64)newp,1,0); /* AT_FDCWD, RENAME_NOREPLACE=1 */
}
static void put64(u8*p,u64 v){for(u32 i=0;i<8;i++)p[i]=(u8)(v>>(8*i));}

/* read [off,off+length) into out, in <=READ_STEP pread calls; EINTR-safe, bounded */
static i64 pread_region(u8*out,u64 length,u64 off) {
    u64 done=0; u32 calls=0;
    while(done<length && ++calls<=300000) {
        u64 want=length-done; if(want>READ_STEP) want=READ_STEP;
        i64 r=sc(67,source,(i64)(out+done),(i64)want,(i64)(off+done),0,0);
        if(r==-4)continue;
        if(r<=0 || (u64)r>want) return r<0?r:-5;
        done+=(u64)r;
    }
    return done==length?0:-11;
}

static i64 open_and_validate(void) {
    source=op(PART_PATH,A64_READ,0); if(source<0)return source;
    i64 r=sc(80,source,(i64)st,0,0,0,0); if(r)return r;          /* fstat */
    if((*(u32*)(st+16)&0170000)!=0060000) return -22;           /* S_IFBLK */
    if(*(u64*)(st+32)!=PART_RDEV) return -22;                    /* st_rdev */
    u64 bytes=0; r=sc(29,source,(i64)0x80081272UL,(i64)&bytes,0,0,0); if(r)return r; /* BLKGETSIZE64 */
    if(bytes!=PART_SIZE) return -22;
    i64 n=read_all(SYS_DEV,idbuf,sizeof(idbuf));
    if(n<0 || (u64)n!=sizeof(DEV_STR)-1 || !same(idbuf,(const u8*)DEV_STR,sizeof(DEV_STR)-1)) return -22;
    n=read_all(SYS_SIZE,idbuf,sizeof(idbuf));
    if(n<0 || (u64)n!=sizeof(SECTORS_STR)-1 || !same(idbuf,(const u8*)SECTORS_STR,sizeof(SECTORS_STR)-1)) return -22;
    sr.flags|=8;
    return 0;
}

/* poll JOB_DIR/ack for the 64 B ACK matching (nonce,index,digest); 300 s cap */
static i64 wait_ack(u64 index,const u8*digest) {
    i64 begin=now();
    for(u32 i=0;i<300001;i++) {
        i64 n=read_all(JOB_DIR "/ack",ackbuf,sizeof(ackbuf));
        if(n>=64) {
            if(n!=64 || !same(ackbuf,(const u8*)"M4SACK01",8) || !same(ackbuf+8,job_nonce,16)
               || *(u64*)(ackbuf+24)!=index || !same(ackbuf+32,digest,32)) return -84;
            return unlink(JOB_DIR "/ack");
        }
        if(n<0 && n!=-2) return n;
        i64 t=now(); if(begin<0||t<begin||t-begin>=ACK_TIMEOUT) return -110;
        i64 r=pause_poll();if(r)return r;
    }
    return -110;
}

/* Publish the complete payload before its separate record. No overwrites. */
static i64 atomic_file(const char*destination,const u8*data,u64 length,int*owner) {
    i64 fd=op(JOB_DIR "/chunk.tmp",A64_CREATE,0600);if(fd<0)return fd;own_tmp=1;
    i64 r=write_all(fd,data,length),c=cl(fd);if(!r)r=c;
    if(r)return r;
    r=renameat2_noreplace(JOB_DIR "/chunk.tmp",destination);
    if(!r){own_tmp=0;*owner=1;}return r;
}
static i64 clean_owned(void) {
    i64 r=0,c;
    if(own_record){c=unlink(JOB_DIR "/chunk.ready");if(c&&c!=-2)r=c;else own_record=0;}
    if(own_data){c=unlink(JOB_DIR "/chunk.bin");if(c&&c!=-2&&!r)r=c;else if(!c||c==-2)own_data=0;}
    if(own_tmp){c=unlink(JOB_DIR "/chunk.tmp");if(c&&c!=-2&&!r)r=c;else if(!c||c==-2)own_tmp=0;}
    return r;
}
static i64 publish(const u8*record,const u8*payload,u64 plen,u64 index,int final) {
    if(final){int owner=0;return atomic_file(JOB_DIR "/done",record,80,&owner);}
    i64 r=atomic_file(JOB_DIR "/chunk.bin",payload,plen,&own_data);if(r)return r;
    r=atomic_file(JOB_DIR "/chunk.ready",record,80,&own_record);if(r)return r;
    r=wait_ack(index,record+48);if(r)return r;
    return clean_owned();
}

void stream_main(u64*stack) {
    for(i64 fd=0;fd<4096;fd++)cl(fd);
    for(u32 i=0;i<8;i++)sr.magic[i]=((const u8*)"M4STR001")[i];
    for(u32 i=0;i<16;i++)sr.nonce[i]=job_nonce[i];
    sr.version=1; sr.phase=1; sr.index=-1;
    sr.euid=sc(175,0,0,0,0,0,0); sr.pid=sc(172,0,0,0,0,0,0); sr.ppid=sc(173,0,0,0,0,0,0);
    if(stack[0]!=2){sr.error=-22;goto done;}
    const char*p=(const char*)stack[2]; u64 value=0; u32 digits=0;
    while(p[digits]&&digits<10){if(p[digits]<'0'||p[digits]>'9'){sr.error=-22;goto done;}value=value*10+p[digits++]-'0';}
    if(!digits||p[digits]||value<=1||value>0x7fffffffUL){sr.error=-22;goto done;} sr.loader_pid=value;
    for(u32 i=0;sr.ppid!=1&&i<100;i++){i64 ts[2]={0,1000000};sc(101,(i64)ts,0,0,0,0,0);sr.ppid=sc(173,0,0,0,0,0,0);}
    if(sr.euid||sr.ppid!=1){sr.error=-13;goto done;}
    sr.cleanup=unlink(JOB_DIR "/worker"); if(sr.cleanup){sr.error=sr.cleanup;goto done;} sr.flags=1;
    sr.error=tmpfs(&fs); if(sr.error)goto done;
    if((u64)fs.bsize*(u64)fs.bavail<16*1024*1024){sr.error=-28;goto done;}sr.flags|=2;
    sr.error=verify_inherited_closed(); if(sr.error)goto done;
    sr.error=save_new(JOB_DIR "/ready",&sr,sizeof(sr),0600); if(sr.error)goto done;
    sr.error=wait_start(); if(sr.error)goto done;
    lifecycle_result.loader_pid=sr.loader_pid; sr.error=inspect_loader(); if(sr.error)goto done; sr.flags|=4;

    sr.error=open_and_validate(); if(sr.error)goto done;

    /* Pass 1: stream chunks, accumulate full SHA (first) */
    struct Sha256 h1; sha_init(&h1);
    sr.phase=3; u64 off=0; u64 idx=0;
    while(off<PART_SIZE) {
        u64 length=PART_SIZE-off; if(length>CHUNK)length=CHUNK;
        sr.error=pread_region(chunk,length,off); if(sr.error)goto done;
        u8 cd[32]; digest_bytes(chunk,length,cd); sha_update(&h1,chunk,length);
        u8 rec[80];
        for(u32 i=0;i<8;i++)rec[i]=((const u8*)"M4CHNK01")[i];
        for(u32 i=0;i<16;i++)rec[8+i]=job_nonce[i];
        put64(rec+24,idx); put64(rec+32,off); put64(rec+40,length);
        for(u32 i=0;i<32;i++)rec[48+i]=cd[i];
        sr.error=publish(rec,chunk,length,idx,0); if(sr.error)goto done;
        off+=length; idx++; sr.offset=off; sr.chunks=idx; sr.index=(i64)idx;
    }
    sha_final(&h1,sr.first); sr.flags|=16;

    /* Pass 2: independent whole-partition re-read; must equal pass 1 */
    sr.phase=4; struct Sha256 h2; sha_init(&h2);
    for(u64 at=0;at<PART_SIZE;) {
        u64 length=PART_SIZE-at; if(length>CHUNK)length=CHUNK;
        sr.error=pread_region(chunk,length,at); if(sr.error)goto done;
        sha_update(&h2,chunk,length); at+=length;
    }
    sha_final(&h2,sr.second);
    if(!same(sr.first,sr.second,32)){sr.error=-84;goto done;} sr.flags|=32;
    sr.error=cl(source);source=-1;if(sr.error)goto done;

    /* Final: DONE record {chunks, size, error=0, digest=first(==second)} */
    {
        u8 rec[80];
        for(u32 i=0;i<8;i++)rec[i]=((const u8*)"M4DONE01")[i];
        for(u32 i=0;i<16;i++)rec[8+i]=job_nonce[i];
        put64(rec+24,idx); put64(rec+32,PART_SIZE); put64(rec+40,0);
        for(u32 i=0;i<32;i++)rec[48+i]=sr.first[i];
        sr.error=publish(rec,0,0,idx,1); if(sr.error)goto done;
    }
    sr.phase=6;
done:
    if(source>=0){i64 c=cl(source);if(!sr.error&&c)sr.error=c;source=-1;}
    /* Preserve preexisting/unowned paths, including malformed ACK evidence. */
    if(sr.error){sr.phase=90;sr.cleanup=clean_owned();}
    save_new(JOB_DIR "/result",&sr,sizeof(sr),0600);
    exit_child(sr.error?1:0);
}

__attribute__((naked,noreturn,visibility("default"))) void _start(void) {
    __asm__ volatile("mov x0,sp\nbl stream_main\nmov x0,#127\nmov x8,#94\nsvc #0");
}
