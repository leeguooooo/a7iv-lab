/* Offline-reviewed lease-only AP loader. No unload, DMA, MMIO or device API.
 * The sole kernel mutation is one init_module of the readonly sealed blob.
 * Its allocation remains resident until reboot, independently of AP cleanup. */
#define _start unused_lifecycle_start
#define worker_main unused_lifecycle_main
#include "lifecycle_worker.c"
#undef worker_main
#undef _start
#include "kernel_module_blob.h"
struct Lease {u8 magic[8],nonce[16];i64 version,stage,error,attempts,load_return,
 version_bytes,status_bytes,disabled_bytes,sig_bytes,initial_state,post_state_bytes,post_status_bytes,page_phys;};
_Static_assert(sizeof(struct Lease)==128,"lease ABI");
static struct Lease lease;
static u8 buf[8193], handshake[65];
static const char *state_path="/sys/module/m4btl_lease_01/initstate";
static const char *status_path="/sys/module/m4btl_lease_01/parameters/status";
static i64 scoped_start(void) {
 i64 begin=now();if(begin<0)return -5;
 for(u32 i=0;i<601;i++) {
  i64 n=read_all(JOB_DIR "/start",handshake,sizeof(handshake));
  if(n>=0) {
   if(n!=64||!same(handshake,(const u8*)"M4KSTART",8)||!same(handshake+8,job_nonce,16)||
      *(u64*)(handshake+24)!=1||!same(handshake+32,(const u8*)lease_scope,32))return -84;
   return unlink(JOB_DIR "/start");
  }
  if(n!=-2)return n;i64 t=now();if(t<begin||t-begin>=60)return -110;
  i64 r=pause_poll();if(r)return r;
 }return -110;
}
static i64 exact(const char*path,const u8*expected,u64 length,i64*count) {
 *count=read_all(path,buf,sizeof(buf));if(*count<0)return *count;
 return (u64)*count==length&&same(buf,expected,length)?0:-84;
}
static i64 capability(void) {
 lease.status_bytes=read_all("/proc/self/status",buf,sizeof(buf));if(lease.status_bytes<0)return lease.status_bytes;
 const char key[]="CapEff:\t";u32 hits=0;u64 caps=0;
 for(u64 i=0;i+8<(u64)lease.status_bytes;i++)if((!i||buf[i-1]=='\n')&&same(buf+i,(const u8*)key,8)) {
  hits++;u64 j=i+8,value=0;u32 digits=0;
  while(j<(u64)lease.status_bytes&&buf[j]!='\n') {
   u8 c=buf[j++];u32 x;if(c>='0'&&c<='9')x=c-'0';else if(c>='a'&&c<='f')x=c-'a'+10;else if(c>='A'&&c<='F')x=c-'A'+10;else return -84;
   if(++digits>16)return -84;value=(value<<4)|x;
  }
  if(!digits||j==(u64)lease.status_bytes)return -84;caps=value;
 }
 return hits==1&&(caps&(1UL<<16))?0:-13;
}
static i64 validate_status(i64 n) {
 const u8*prefix=(const u8*)lease_status_prefix;u64 k=sizeof(lease_status_prefix)-1;
 if(n<0)return n;if((u64)n<k+1+sizeof(" resident=boot dma=0\n\n")-1||!same(buf,prefix,k))return -84;
 u64 value=0;u32 digits=0;
 while(k<(u64)n&&buf[k]!=' ') {
  u8 c=buf[k++];u32 x;if(c>='0'&&c<='9')x=c-'0';else if(c>='a'&&c<='f')x=c-'a'+10;else return -84;
  if(++digits>16)return -84;value=(value<<4)|x;
 }
 const u8 suffix[]=" resident=boot dma=0\n\n";
 if(!digits||(u64)n-k!=sizeof(suffix)-1||!same(buf+k,suffix,sizeof(suffix)-1)||value<0x400000000UL||value>0x4fffff000UL||(value&4095))return -84;
 lease.page_phys=(i64)value;return 0;
}
static i64 load_lease(void) {
 lease.stage=1;i64 r=exact("/proc/version",expected_version,sizeof(expected_version),&lease.version_bytes);if(r)return r;
 r=capability();if(r)return r;
 r=exact("/proc/sys/kernel/modules_disabled",(const u8*)"0\n",2,&lease.disabled_bytes);if(r)return r;
 r=exact("/sys/module/module/parameters/sig_enforce",(const u8*)"N\n",2,&lease.sig_bytes);if(r)return r;
 lease.initial_state=read_all(state_path,buf,sizeof(buf));if(lease.initial_state!=-2)return lease.initial_state<0?lease.initial_state:-17;
 lease.stage=2;lease.attempts=1;
 /* Raw AArch64 init_module, no force/flags, empty immutable parameters. */
 lease.load_return=sc(105,(i64)kernel_lease_module,sizeof(kernel_lease_module),(i64)"",0,0,0);
 lease.stage=3;
 if(lease.load_return)return lease.load_return<0?lease.load_return:-5;
 lease.post_state_bytes=read_all(state_path,buf,sizeof(buf));
 if(lease.post_state_bytes!=5||!same(buf,(const u8*)"live\n",5))return -117;
 lease.post_status_bytes=read_all(status_path,buf,sizeof(buf));
 /* Preserve every readable raw status before strict legacy-wire validation.
    Legacy getter supplies LF; actual param_attr_show appends a second LF. */
 if(lease.post_status_bytes>=0) {
  r=save_new(JOB_DIR "/module_status",buf,(u64)lease.post_status_bytes,0600);if(r)return -117;
 }
 r=validate_status(lease.post_status_bytes);if(r)return -117;
 lease.stage=4;return 0;
}
static void cleanup(const char*p) {i64 r=unlink(p);if(r&&r!=-2&&!result.cleanup)result.cleanup=r;}
void kernel_lease_main(u64*stack) {
 for(i64 fd=0;fd<4096;fd++)cl(fd);
 for(u32 i=0;i<8;i++){result.magic[i]=((const u8*)"M4KLS001")[i];lease.magic[i]=((const u8*)"M4KLEAS1")[i];}
 for(u32 i=0;i<16;i++){result.nonce[i]=job_nonce[i];lease.nonce[i]=job_nonce[i];}
 result.version=lease.version=1;result.phase=1;lease.load_return=-999;
 result.euid=sc(175,0,0,0,0,0,0);result.pid=sc(172,0,0,0,0,0,0);result.ppid=sc(173,0,0,0,0,0,0);
 if(stack[0]!=2){result.error=-22;goto finished;}
 const char*p=(const char*)stack[2];u64 v=0;u32 digits=0;
 while(p[digits]&&digits<10){if(p[digits]<'0'||p[digits]>'9'){result.error=-22;goto finished;}v=v*10+p[digits++]-'0';}
 if(!digits||p[digits]||v<=1||v>0x7fffffffUL){result.error=-22;goto finished;}result.loader_pid=v;
 for(u32 i=0;result.ppid!=1&&i<100;i++){i64 ts[2]={0,1000000};sc(101,(i64)ts,0,0,0,0,0);result.ppid=sc(173,0,0,0,0,0,0);}
 if(result.ppid!=1||result.euid){result.error=-13;goto finished;}
 result.cleanup=unlink(JOB_DIR "/worker");if(result.cleanup){result.error=result.cleanup;goto finished;}
 result.error=tmpfs(&fs);if(result.error)goto finished;result.fs_available=fs.bsize*fs.bavail;
 result.error=verify_inherited_closed();if(result.error)goto finished;
 result.error=save_new(JOB_DIR "/ready",&result,sizeof(result),0600);if(result.error)goto finished;
 result.phase=2;result.error=scoped_start();if(result.error)goto finished;
 result.phase=3;result.error=inspect_loader();if(result.error)goto finished;
 result.error=load_lease();if(!result.error)result.phase=4;
finished:
 lease.error=result.error;if(result.error)result.phase=90;
 save_new(JOB_DIR "/lease",&lease,sizeof(lease),0600);
 save_new(JOB_DIR "/result",&result,sizeof(result),0600);
 /* Always allow acknowledgement/cleanup, including rejected/unknown loads.
    Cleanup never removes a kernel module or frees its resident page. */
 i64 begin=now();for(u32 i=0;i<601;i++) {
  i64 n=read_all(JOB_DIR "/ack",command,sizeof(command));
  if(n==32&&same(command,(const u8*)"M4KACK01",8)&&same(command+8,job_nonce,16)&&*(u64*)(command+24)==1)break;
  i64 t=now();if(begin<0||t<begin||t-begin>=60)break;pause_poll();
 }
 cleanup(JOB_DIR "/module_status");cleanup(JOB_DIR "/lease");cleanup(JOB_DIR "/start");cleanup(JOB_DIR "/ack");
 result.phase=5;result.error=result.cleanup;save_new(JOB_DIR "/cleaned",&result,sizeof(result),0600);exit_child(result.error?1:0);
}
__attribute__((naked,noreturn,visibility("default"))) void _start(void) {
 __asm__ volatile("mov x0,sp\nbl kernel_lease_main\nmov x0,#127\nmov x8,#94\nsvc #0");
}
