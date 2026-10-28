/* Read-only backups of five fixed block nodes. No block write/mount/freeze.
 * Helper sources: Erlla MIT. Mounted sources require two identical full reads;
 * this is per-partition consistency, not an atomic whole-camera snapshot.
 */
#define _start unused_lifecycle_start
#define worker_main unused_lifecycle_main
#define result lifecycle_result
#include "lifecycle_worker.c"
#undef result
#undef worker_main
#undef _start
#include "sha256.h"
struct BackupResult {u8 magic[8],nonce[16];i64 version,phase,error,euid,pid,ppid,loader_pid,cleanup,index,bytes,chunks,flags;u8 first[32],second[32];};
_Static_assert(sizeof(struct BackupResult)==184,"backup ABI");
static struct BackupResult br;
static u8 snapshot[32*1024*1024],digests[1024*32],buffer[65536],st[128],mounts[131073];
static i64 source=-1;
static u32 count=0;
static void name(char*out,const char*kind,u32 index,i64 chunk) {
    const char*base=JOB_DIR "/";u32 n=0;
    while(base[n]) {out[n]=base[n];n++;}
    for(u32 i=0;kind[i];i++)out[n++]=kind[i];out[n++]=(char)('0'+index);
    if(chunk>=0) {out[n++]='c';for(u32 i=0;i<4;i++){out[n+3-i]=(char)('0'+chunk%10);chunk/=10;}n+=4;}
    out[n]=0;
}
static i64 pread_exact(i64 fd,u8*out,u64 length,u64 off) {
    u64 done=0;u32 calls=0;
    while(done<length&&++calls<=4096) {
        i64 r=sc(67,fd,(i64)(out+done),length-done,off+done,0,0);
        if(r==-4)continue;if(r<=0||(u64)r>length-done)return r<0?r:-5;done+=(u64)r;
    }
    return done==length?0:-11;
}
static i64 capture(u32 index) {
    const struct Target*t=&targets[index];
    if(!t->size||t->size>sizeof(snapshot))return -22;
    source=op(t->path,A64_READ,0);if(source<0)return source;
    i64 r=sc(80,source,(i64)st,0,0,0,0);if(r)return r;
    if((*(u32*)(st+16)&0170000)!=0060000||*(u64*)(st+32)!=t->rdev)return -22;
    u64 bytes=0;r=sc(29,source,0x80081272UL,(i64)&bytes,0,0,0);if(r)return r;if(bytes!=t->size)return -22;
    i64 n=read_all(t->sysdev,buffer,sizeof(buffer));
    if(n<0||(u64)n!=t->devlen||!same(buffer,(const u8*)t->dev,t->devlen))return -22;
    n=read_all(t->syssize,buffer,sizeof(buffer));
    if(n<0||(u64)n!=t->sectorlen||!same(buffer,(const u8*)t->sectors,t->sectorlen))return -22;br.flags|=8;
    for(u64 at=0;at<t->size;) {
        u64 length=t->size-at;if(length>sizeof(buffer))length=sizeof(buffer);
        r=pread_exact(source,snapshot+at,length,at);if(r)return r;at+=length;br.bytes=at;
    }
    digest_bytes(snapshot,t->size,br.first);br.flags|=16;
    struct Sha256 hash;sha_init(&hash);
    for(u64 at=0;at<t->size;) {
        u64 length=t->size-at;if(length>sizeof(buffer))length=sizeof(buffer);
        r=pread_exact(source,buffer,length,at);if(r)return r;sha_update(&hash,buffer,length);at+=length;
    }
    sha_final(&hash,br.second);if(!same(br.first,br.second,32))return -84;br.flags|=32;
    r=cl(source);source=-1;if(r)return r;
    count=(u32)((t->size+32767)/32768);if(count>1024)return -22;
    for(u32 i=0;i<count;i++) {
        u64 at=(u64)i*32768,length=t->size-at;if(length>32768)length=32768;
        digest_bytes(snapshot+at,length,digests+32*i);char path[128];name(path,"t",index,i);
        r=save_new(path,snapshot+at,length,0600);if(r)return r;br.chunks=i+1;
    }
    char path[128];name(path,"digests",index,-1);
    r=save_new(path,digests,(u64)count*32,0600);if(r)return r;br.flags|=64;return 0;
}
static void clean(u32 index) {
    for(u32 i=0;i<count;i++) {char path[128];name(path,"t",index,i);i64 r=unlink(path);if(r&&r!=-2&&!br.cleanup)br.cleanup=r;}
    char path[128];name(path,"digests",index,-1);i64 r=unlink(path);if(r&&r!=-2&&!br.cleanup)br.cleanup=r;
}
static i64 wait_ack(u32 index) {
    char path[128];name(path,"ack",index,-1);i64 begin=now();
    for(u32 i=0;i<3001;i++) {
        i64 n=read_all(path,command,sizeof(command));
        if(n>=32) {
            if(n!=32||!same(command,(const u8*)"M4ACK001",8)||!same(command+8,job_nonce,16)||*(u64*)(command+24)!=index+1)return -84;
            return unlink(path);
        }
        if(n<0&&n!=-2)return n;
        i64 t=now();if(begin<0||t<begin||t-begin>=300)return -110;pause_poll();
    }
    return -110;
}
void backup_main(u64*stack) {
    for(i64 fd=0;fd<4096;fd++)cl(fd);
    for(u32 i=0;i<8;i++)br.magic[i]=((const u8*)"M4BKP001")[i];for(u32 i=0;i<16;i++)br.nonce[i]=job_nonce[i];
    br.version=1;br.phase=1;br.index=-1;br.euid=sc(175,0,0,0,0,0,0);br.pid=sc(172,0,0,0,0,0,0);br.ppid=sc(173,0,0,0,0,0,0);
    if(stack[0]!=2){br.error=-22;goto done;}const char*p=(const char*)stack[2];u64 value=0;u32 digits=0;
    while(p[digits]&&digits<10){if(p[digits]<'0'||p[digits]>'9'){br.error=-22;goto done;}value=value*10+p[digits++]-'0';}
    if(!digits||p[digits]||value<=1||value>0x7fffffffUL){br.error=-22;goto done;}br.loader_pid=value;
    for(u32 i=0;br.ppid!=1&&i<100;i++){i64 ts[2]={0,1000000};sc(101,(i64)ts,0,0,0,0,0);br.ppid=sc(173,0,0,0,0,0,0);}
    if(br.euid||br.ppid!=1){br.error=-13;goto done;}
    br.cleanup=unlink(JOB_DIR "/worker");if(br.cleanup){br.error=br.cleanup;goto done;}br.flags=1;
    br.error=tmpfs(&fs);if(br.error)goto done;
    if((u64)fs.bsize*(u64)fs.bavail<80*1024*1024){br.error=-28;goto done;}br.flags|=2;
    br.error=verify_inherited_closed();if(br.error)goto done;
    br.error=save_new(JOB_DIR "/ready",&br,sizeof(br),0600);if(br.error)goto done;
    br.error=wait_start();if(br.error)goto done;
    lifecycle_result.loader_pid=br.loader_pid;br.error=inspect_loader();if(br.error)goto done;br.flags|=4;
    i64 length=read_all("/proc/self/mountinfo",mounts,sizeof(mounts));if(length<=0){br.error=length?length:-22;goto done;}
    br.error=save_new(JOB_DIR "/mountinfo",mounts,length,0600);if(br.error)goto done;
    for(u32 i=0;i<5;i++) {
        br.index=i;br.phase=3;br.bytes=br.chunks=0;br.flags=7;count=0;
        br.error=capture(i);if(br.error)goto done;
        br.phase=4;char path[128];name(path,"part",i,-1);
        br.error=save_new(path,&br,sizeof(br),0600);if(br.error)goto done;
        br.error=wait_ack(i);if(br.error)goto done;
        clean(i);if(br.cleanup){br.error=br.cleanup;goto done;}
        br.phase=5;name(path,"cleaned",i,-1);br.error=save_new(path,&br,sizeof(br),0600);if(br.error)goto done;
    }
    br.phase=6;
done:
    if(source>=0){i64 c=cl(source);if(!br.error&&c)br.error=c;}
    if(br.error){br.phase=90;if(br.index>=0)clean((u32)br.index);}
    save_new(JOB_DIR "/result",&br,sizeof(br),0600);exit_child(br.error?1:0);
}
__attribute__((naked,noreturn,visibility("default"))) void _start(void) {
    __asm__ volatile("mov x0,sp\nbl backup_main\nmov x0,#127\nmov x8,#94\nsvc #0");
}
