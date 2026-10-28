/* OFFLINE CANDIDATE: device execution requires a new explicit scope confirmation.
 * Raw ABI matches the audited normal SDK. No dynamic library is loaded.
 * IPCmap is the fixed 2 MiB global OSAL pool, never dereferenced here.
 */
#define _start unused_lifecycle_start
#define worker_main unused_lifecycle_main
#include "lifecycle_worker.c"
#undef worker_main
#undef _start
struct Envelope {u32 selector,pad;u64 args;};
struct Dynamic {u32 operation,label;u64 value;};
struct Receive {u64 output;u32 timeout,pad;};
struct Probe {
    i64 version,profile,label,open_rc,init_rc,map_rc,alloc_rc,recv_rc,free_rc,unmap_rc,close_rc;
    u64 init_words[2],id,message,unknown,completed;
};
_Static_assert(sizeof(struct Envelope)==16 && sizeof(struct Dynamic)==16 && sizeof(struct Receive)==16,"OSAL packets");
static struct Probe probe;
static i64 call_ioctl(i64 fd,u32 command,u32 selector,void*args) {
    struct Envelope e={selector,0,(u64)args};
    /* No EINTR/-0x3fd retry: preserve one-shot raw outcome. */
    return sc(29,fd,command,(i64)&e,0,0,0);
}
__attribute__((used,noinline,visibility("default")))
i64 osal_candidate_sequence(struct Probe*p,u32 label,u32 ipcmap) {
    p->version=1;p->profile=ipcmap;p->label=label;
    p->open_rc=p->init_rc=p->map_rc=p->alloc_rc=p->recv_rc=p->free_rc=p->unmap_rc=p->close_rc=-999;
    p->init_words[0]=p->init_words[1]=p->id=p->message=p->unknown=p->completed=0;
    /* SID is a label, not a borrowed queue. 0x3f is also used by kernel init. */
    if(!label||label>0x7fff||ipcmap!=1)return -95;
    i64 r=-5,fd=op("/dev/uipc",2|A64_O_CLOEXEC|A64_O_NOFOLLOW,0),mapped=-1;
    p->open_rc=fd;if(fd<0)return fd;
    u32 init[4]={0,0,0,0};p->init_rc=call_ioctl(fd,0x80000010,0,init);
    p->init_words[0]=(u64)init[0]|((u64)init[1]<<32);p->init_words[1]=(u64)init[2]|((u64)init[3]<<32);
    if(p->init_rc){p->unknown|=1;r=p->init_rc;goto close;}
    if(init[0]!=0x200000||init[1]!=0x80000||init[2]!=0x20000||!init[3]){p->unknown|=2;r=-84;goto close;}
    mapped=sc(222,0,0x200000,3,1,fd,0);p->map_rc=mapped;
    if((u64)mapped>=(u64)-4095){p->unknown|=4;r=mapped;mapped=-1;goto close;}
    /* A zero map base cannot satisfy the kernel dispatcher. Do not replace it. */
    if(!mapped){p->unknown|=8;r=-84;goto unmap;}
    u32 id=0;struct Dynamic d={0x2a,label,(u64)&id};
    p->alloc_rc=call_ioctl(fd,0x8000000c,0,&d);p->id=id;
    if(p->alloc_rc){p->unknown|=16;r=p->alloc_rc;goto unmap;}
    if(id==init[3]||!(id&0x80000000U)||!(id&0x7fff)||((id>>16)&0x7fff)!=label){p->unknown|=32;r=-84;goto unmap;}
    u64 message=0;struct Receive q={(u64)&message,0,0};
    p->recv_rc=call_ioctl(fd,0x80000007,id,&q);p->message=message;
    /* Unexpected success/payload is not an empty queue. Never free a guessed
       message/ID or silently discard it. An extra recipient may remain. */
    if(p->recv_rc!=-0x3fe||message){p->unknown|=64;r=p->recv_rc?p->recv_rc:-84;goto unmap;}
    d.operation=0x4a;d.label=0;d.value=id;
    p->free_rc=call_ioctl(fd,0x8000000c,0,&d);
    if(p->free_rc){p->unknown|=128;r=p->free_rc;goto unmap;}
    p->completed=1;r=0;
unmap:
    p->unmap_rc=sc(215,mapped,0x200000,0,0,0,0);
    if(p->unmap_rc){p->unknown|=256;if(!r)r=p->unmap_rc;}
close:
    p->close_rc=cl(fd);if(p->close_rc){p->unknown|=512;if(!r)r=p->close_rc;}
    return r;
}
void osal_probe_main(u64*stack) {
    for(i64 fd=0;fd<4096;fd++)cl(fd);
    for(u32 i=0;i<8;i++)result.magic[i]=((const u8*)"M4OSAL01")[i];
    for(u32 i=0;i<16;i++)result.nonce[i]=job_nonce[i];
    result.version=1;result.phase=1;result.euid=sc(175,0,0,0,0,0,0);
    result.pid=sc(172,0,0,0,0,0,0);result.ppid=sc(173,0,0,0,0,0,0);
    if(stack[0]!=2){result.error=-22;goto finished;}
    const char*p=(const char*)stack[2];u64 value=0;u32 n=0;
    while(p[n]&&n<10){if(p[n]<'0'||p[n]>'9'){result.error=-22;goto finished;}value=value*10+p[n++]-'0';}
    if(!n||p[n]||value<=1||value>0x7fffffffUL){result.error=-22;goto finished;}result.loader_pid=value;
    for(u32 i=0;result.ppid!=1&&i<100;i++){i64 ts[2]={0,1000000};sc(101,(i64)ts,0,0,0,0,0);result.ppid=sc(173,0,0,0,0,0,0);}
    if(result.ppid!=1||result.euid){result.error=-13;goto finished;}
    result.cleanup=unlink(JOB_DIR "/worker");if(result.cleanup){result.error=result.cleanup;goto finished;}
    result.error=tmpfs(&fs);if(result.error)goto finished;result.fs_available=fs.bsize*fs.bavail;
    result.error=verify_inherited_closed();if(result.error)goto finished;
    result.error=save_new(JOB_DIR "/ready",&result,sizeof(result),0600);if(result.error)goto finished;
    result.phase=2;result.error=wait_start();if(result.error)goto finished;
    result.phase=3;result.error=inspect_loader();if(result.error)goto finished;
    /* A distinct bitmap-allocated QID is mandatory; never reuse bootstrap ID. */
    result.error=osal_candidate_sequence(&probe,0x3f,1);
    {i64 saved=save_new(JOB_DIR "/probe",&probe,sizeof(probe),0600);if(saved&&!result.error)result.error=saved;}
    if(!result.error)result.phase=4;
finished:
    if(result.error)result.phase=90;
    save_new(JOB_DIR "/result",&result,sizeof(result),0600);
    /* Lifecycle ACK does not authorize a second OSAL action. */
    i64 begin=now();
    for(u32 i=0;i<601;i++){
        i64 n=read_all(JOB_DIR "/ack",command,sizeof(command));
        if(n==32&&same(command,(const u8*)"M4ACK001",8)&&same(command+8,job_nonce,16)&&*(u64*)(command+24)==1)break;
        i64 t=now();if(begin<0||t<begin||t-begin>=60)break;pause_poll();
    }
    {i64 c=unlink(JOB_DIR "/probe");if(c&&c!=-2&&!result.cleanup)result.cleanup=c;}
    {i64 c=unlink(JOB_DIR "/ack");if(c&&c!=-2&&!result.cleanup)result.cleanup=c;}
    if(!result.error&&result.cleanup)result.error=result.cleanup;
    result.phase=5;save_new(JOB_DIR "/cleaned",&result,sizeof(result),0600);exit_child(result.error?1:0);
}
__attribute__((naked,noreturn,visibility("default"))) void _start(void) {
    __asm__ volatile("mov x0,sp\nbl osal_probe_main\nmov x0,#127\nmov x8,#94\nsvc #0");
}
