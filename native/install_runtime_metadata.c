/* Fixed metadata only: never opens /dev nodes, issues ioctl, or writes RAM. */
#include "linux_a64.h"
#include "job.h"
#include "sha256.h"
struct Wire {u8 magic[8],nonce[16];i64 version,phase,error,euid,pid,ppid,loader_pid,cleanup,flags,proc_bytes,alias_bytes;u8 proc_sha[32],alias_sha[32];};
struct Alias {u64 number,length,mode,rdev;u8 target[128],stat_raw[128];};
_Static_assert(sizeof(struct Wire)==176,"wire ABI");
_Static_assert(sizeof(struct Alias)==288,"alias ABI");
/* Linux asm-generic stat, arm64 LP64: offsets independently checked by verifier. */
struct A64Stat {u64 dev,ino;u32 mode,nlink,uid,gid;u64 rdev,pad; i64 size;u32 blksize,pad2;i64 blocks,atime;u64 atimens;i64 mtime;u64 mtimens;i64 ctime;u64 ctimens;u32 unused[2];};
_Static_assert(sizeof(struct A64Stat)==128 && __builtin_offsetof(struct A64Stat,mode)==16 && __builtin_offsetof(struct A64Stat,rdev)==32,"arm64 stat ABI");
static struct Wire wr;static struct Alias aliases[6];static u8 proc[65537],command[33];
static const u64 numbers[6]={1,3,5,7,8,15};static struct Fs fs;
static i64 atomic(const char*pending,const char*published,const void*data,u64 length){i64 r=save_new(pending,data,length,0600);if(r)return r;return sc(276,-100,(i64)pending,-100,(i64)published,1,0);}
static i64 now(void){i64 ts[2];i64 r=sc(113,1,(i64)ts,0,0,0,0);return r?r:ts[0];}
static i64 wait_start(void){i64 begin=now();if(begin<0)return begin;for(u32 i=0;i<601;i++){i64 n=read_all(JOB_DIR "/start",command,sizeof(command));if(n>=0){if(n!=32||!same(command,(u8*)"M4MSTART",8)||!same(command+8,job_nonce,16)||*(u64*)(command+24)!=1)return -84;return unlink(JOB_DIR "/start");}if(n!=-2)return n;i64 t=now();if(t<begin||t-begin>=60)return -110;i64 delay[2]={0,100000000};i64 r=sc(101,(i64)delay,0,0,0,0,0);if(r&&r!=-4)return r;}return -110;}
static i64 sample(struct Alias*a,u64 number){char path[40]="/dev/nflasha";decimal(path+12,number);a->number=number;i64 n=sc(78,-100,(i64)path,(i64)a->target,sizeof(a->target),0,0);if(n<=0||n>=128)return n<0?n:-75;a->length=n;char allowed[40]="/dev/cnflasha";u32 len=13+decimal(allowed+13,number);int valid=0;for(u32 kind=0;kind<2;kind++){allowed[5]=kind?'p':'c';if((n==len&&same(a->target,(u8*)allowed,len))||(n==len-5&&same(a->target,(u8*)allowed+5,len-5)))valid=1;}if(!valid)return -84;struct A64Stat st={0}; i64 r=sc(79,-100,(i64)path,(i64)&st,0,0,0);if(r)return r;if((st.mode&0170000)!=0060000)return -22;a->mode=st.mode;a->rdev=st.rdev;for(u32 i=0;i<128;i++)a->stat_raw[i]=((u8*)&st)[i];return 0;}
void metadata_main(u64*stack){for(i64 fd=0;fd<4096;fd++)cl(fd);for(u32 i=0;i<8;i++)wr.magic[i]="M4META01"[i];for(u32 i=0;i<16;i++)wr.nonce[i]=job_nonce[i];wr.version=1;wr.phase=1;wr.euid=sc(175,0,0,0,0,0,0);wr.pid=sc(172,0,0,0,0,0,0);wr.ppid=sc(173,0,0,0,0,0,0);if(stack[0]!=2){wr.error=-22;goto done;}const char*p=(char*)stack[2];u64 v=0;u32 n=0;while(p[n]&&n<10){if(p[n]<'0'||p[n]>'9'){wr.error=-22;goto done;}v=v*10+p[n++]-'0';}if(!n||p[n]||v<=1||v>0x7fffffffUL){wr.error=-22;goto done;}wr.loader_pid=v;for(u32 i=0;wr.ppid!=1&&i<100;i++){i64 d[2]={0,1000000};sc(101,(i64)d,0,0,0,0,0);wr.ppid=sc(173,0,0,0,0,0,0);}if(wr.ppid!=1||wr.euid){wr.error=-13;goto done;}wr.cleanup=unlink(JOB_DIR "/worker");if(wr.cleanup){wr.error=wr.cleanup;goto done;}wr.error=tmpfs(&fs);if(wr.error)goto done;wr.flags=13;wr.error=atomic(JOB_DIR "/ready.pending",JOB_DIR "/ready",&wr,sizeof(wr));if(wr.error)goto done;wr.error=wait_start();if(wr.error)goto done;wr.flags|=16;
for(u32 i=0;i<6;i++){wr.error=sample(&aliases[i],numbers[i]);if(wr.error)goto done;}
wr.proc_bytes=read_all("/proc/partitions",proc,sizeof(proc));if(wr.proc_bytes<=0){wr.error=wr.proc_bytes?wr.proc_bytes:-5;goto done;}
for(u32 i=0;i<6;i++){struct Alias after={0};wr.error=sample(&after,numbers[i]);if(wr.error)goto done;if(after.length!=aliases[i].length||after.mode!=aliases[i].mode||after.rdev!=aliases[i].rdev||!same(after.stat_raw,aliases[i].stat_raw,16)||!same(after.target,aliases[i].target,after.length)){wr.error=-116;goto done;}}
wr.alias_bytes=sizeof(aliases);digest_bytes(proc,wr.proc_bytes,wr.proc_sha);digest_bytes((u8*)aliases,sizeof(aliases),wr.alias_sha);wr.error=atomic(JOB_DIR "/partitions.pending",JOB_DIR "/partitions.bin",proc,wr.proc_bytes);if(wr.error)goto done;wr.error=atomic(JOB_DIR "/aliases.pending",JOB_DIR "/aliases.bin",aliases,sizeof(aliases));if(wr.error)goto done;wr.flags|=32;wr.phase=7;
done:if(wr.error)wr.phase=90;i64 r=atomic(JOB_DIR "/result.pending",JOB_DIR "/result",&wr,sizeof(wr));exit_child(wr.error||r?1:0);}
__attribute__((naked,noreturn,visibility("default"))) void _start(void){__asm__ volatile("mov x0,sp\nbl metadata_main\nmov x0,#127\nmov x8,#94\nsvc #0");}
