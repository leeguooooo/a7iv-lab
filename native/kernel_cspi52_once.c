/* OFFLINE CSPI52 candidate: one sealed module load then one fixed nonce submit.
 * No device access, unload, reset, free, retry or arbitrary-address input.
 * All kernel objects remain resident until reboot, separate from AP cleanup. */
#define _start unused_lifecycle_start
#define worker_main unused_lifecycle_main
#include "lifecycle_worker.c"
#undef worker_main
#undef _start
#include "kernel_module_blob.h"
struct Lease {u8 magic[8],nonce[16];i64 version,stage,error,attempts,load_return,
 version_bytes,status_bytes,disabled_bytes,sig_bytes,initial_state,post_state_bytes,post_status_bytes,page_phys;};
_Static_assert(sizeof(struct Lease)==128,"lease ABI");
static u8 buf[8193], handshake[65];
static struct Lease lease; /* preflight counters, no hardware handles */
struct Cspi {u8 magic[8],nonce[16];i64 version,stage,error,loads,load_return,submits,write_return,polls,snapshots,page_phys,state,reserved,done,err,rc,raw_valid;u8 raw[52],padding[4];};
_Static_assert(sizeof(struct Cspi)==208,"CSPI report ABI");
static struct Cspi cspi;
static const char *submit_path="/sys/module/m4btl_cspi52_01/parameters/submit";
static u64 cursor,limit;
static u32 status_index;
static void status_name(char*out,u32 i) {
 const char*p=JOB_DIR "/status";u32 n=0;while(p[n]){out[n]=p[n];n++;}
 out[n++]='0'+i/10;out[n++]='0'+i%10;out[n]=0;
}
static int literal(const char*s) {
 for(u64 j=0;s[j];j++) {if(cursor>=limit||buf[cursor++]!=(u8)s[j])return 0;}return 1;
}
static int decimal_value(i64*out) {
 int neg=0;u64 v=0;u32 digits=0;if(cursor<limit&&buf[cursor]=='-'){cursor++;neg=1;}
 u64 first=cursor;
 while(cursor<limit&&buf[cursor]>='0'&&buf[cursor]<='9') {v=v*10+buf[cursor++]-'0';if(++digits>10||v>(neg?2147483648UL:2147483647UL))return 0;}
 if(!digits||(digits>1&&buf[first]=='0')||(neg&&!v))return 0;*out=neg?-(i64)v:(i64)v;return 1;
}
static int hex_value(u64*out,u32 exact_digits) {
 u64 v=0;u32 digits=0;u64 first=cursor;
 while(cursor<limit) {u8 c=buf[cursor];u32 x;if(c>='0'&&c<='9')x=c-'0';else if(c>='a'&&c<='f')x=c-'a'+10;else break;
  cursor++;if(++digits>16)return 0;v=(v<<4)|x;}
 if(!digits||(exact_digits&&digits!=exact_digits)||(!exact_digits&&digits>1&&buf[first]=='0'))return 0;*out=v;return 1;
}
static const char *state_path="/sys/module/m4btl_cspi52_01/initstate";
static const char *status_path="/sys/module/m4btl_cspi52_01/parameters/status";
static i64 scoped_start(void) {
 i64 begin=now();if(begin<0)return -5;
 for(u32 i=0;i<601;i++) {
  i64 n=read_all(JOB_DIR "/start",handshake,sizeof(handshake));
  if(n>=0) {
   if(n!=64||!same(handshake,(const u8*)"M4CSTART",8)||!same(handshake+8,job_nonce,16)||
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
/* Status getter has NO LF; actual param_attr_show appends exactly one LF. */
static i64 parse_status(i64 n) {
 if(n<0)return n;cursor=0;limit=(u64)n;u64 pa;i64 submitted,done,err,rc,valid;int state=0;u8 payload[52];int allzero=1;
 if(!literal(cspi_prefix))return -84;
 if(literal("ready"))state=1;else {cursor=sizeof(cspi_prefix)-1;
  if(literal("pending"))state=2;else {cursor=sizeof(cspi_prefix)-1;
   if(literal("done"))state=3;else {cursor=sizeof(cspi_prefix)-1;
    if(literal("error"))state=4;else {cursor=sizeof(cspi_prefix)-1;if(literal("submit-error"))state=5;}}}}
 if(!state||!literal(" page_bytes=4096 page_phys=0x")||!hex_value(&pa,0)||pa<0x400000000UL||pa>0x4fffff000UL||(pa&4095))return -84;
 if(!literal(" submitted=")||!decimal_value(&submitted)||!literal(" done=")||!decimal_value(&done)||!literal(" err=")||!decimal_value(&err)||!literal(" rc=")||!decimal_value(&rc)||!literal(" raw_valid=")||!decimal_value(&valid)||!literal(" raw="))return -84;
 for(u32 i=0;i<52;i++) {
  u8 value=0;for(u32 j=0;j<2;j++) {
   if(cursor>=limit)return -84;u8 c=buf[cursor++];u32 digit;
   if(c>='0'&&c<='9')digit=c-'0';else if(c>='a'&&c<='f')digit=c-'a'+10;else return -84;
   value=(value<<4)|digit;
  }payload[i]=value;if(value)allzero=0;
 }
 if(!literal(" resident=boot source=0x4011e74d4 pci=0 dmac=4 size=52\n")||cursor!=limit)return -84;
 if((submitted!=0&&submitted!=1)||(done!=0&&done!=1)||(valid!=0&&valid!=1))return -84;
 if(state==1&&(submitted||done||err||rc!=-115||valid||!allzero))return -84;
 if(state==2&&(submitted!=1||done||err||rc||valid||!allzero))return -84;
 if(state==3&&(submitted!=1||done!=1||err||rc||valid!=1))return -84;
 if(state==4&&(submitted!=1||done!=1||!err||rc||valid||!allzero))return -84;
 if(state==5&&(submitted!=1||!rc||valid||!allzero||(!done&&err)))return -84;
 if(cspi.page_phys&&pa!=(u64)cspi.page_phys)return -84;
 cspi.page_phys=pa;cspi.state=state;cspi.done=done;cspi.err=err;cspi.rc=rc;cspi.raw_valid=valid;
 for(u32 i=0;i<52;i++)cspi.raw[i]=payload[i];return 0;
}
static i64 snapshot(void) {
 i64 n=read_all(status_path,buf,sizeof(buf));
 if(n>=0) {char path[128];status_name(path,status_index++);i64 r=save_new(path,buf,(u64)n,0600);cspi.snapshots=status_index;if(r)return r;}
 return parse_status(n);
}
static i64 load_lease(void) {
 cspi.stage=1;i64 r=exact("/proc/version",expected_version,sizeof(expected_version),&lease.version_bytes);if(r)return r;
 r=capability();if(r)return r;
 r=exact("/proc/sys/kernel/modules_disabled",(const u8*)"0\n",2,&lease.disabled_bytes);if(r)return r;
 r=exact("/sys/module/module/parameters/sig_enforce",(const u8*)"N\n",2,&lease.sig_bytes);if(r)return r;
 lease.initial_state=read_all(state_path,buf,sizeof(buf));if(lease.initial_state!=-2)return lease.initial_state<0?lease.initial_state:-17;
 r=save_new(JOB_DIR "/load_intent",job_nonce,sizeof(job_nonce),0600);if(r)return r;
 cspi.stage=2;cspi.loads=1;cspi.load_return=sc(105,(i64)kernel_lease_module,sizeof(kernel_lease_module),(i64)"",0,0,0);
 cspi.stage=3;if(cspi.load_return)return cspi.load_return<0?cspi.load_return:-5;
 lease.post_state_bytes=read_all(state_path,buf,sizeof(buf));if(lease.post_state_bytes!=5||!same(buf,(const u8*)"live\n",5))return -117;
 r=snapshot();if(r)return r;if(cspi.state!=1)return -84;
 r=save_new(JOB_DIR "/submit_intent",(const u8*)cspi_nonce,32,0600);if(r)return r;
 cspi.stage=4;cspi.submits=1;
 /* Exactly ONE raw write; no write_all, no retry on EINTR/short/unknown. */
 i64 fd=op(submit_path,A64_READ|1,0);if(fd<0){cspi.write_return=fd;return fd;}
 cspi.write_return=sc(64,fd,(i64)cspi_nonce,32,0,0,0);i64 c=cl(fd);
 cspi.stage=5;
 for(u32 i=0;i<50;i++) {
  cspi.polls++;r=snapshot();if(r)return r;
  if(cspi.state==3){if(cspi.write_return!=32||c)return -117;cspi.stage=6;return 0;}
  if(cspi.state==4||cspi.state==5)return -117;
  if(cspi.state!=2)return -84;
  if(cspi.write_return!=32||c)return -117;
  r=pause_poll();if(r)return r;
 }
 return -110; /* Pending objects remain untouched until reboot. */
}
static void cleanup(const char*p) {i64 r=unlink(p);if(r&&r!=-2&&!result.cleanup)result.cleanup=r;}
void cspi52_main(u64*stack) {
 for(i64 fd=0;fd<4096;fd++)cl(fd);
 for(u32 i=0;i<8;i++){result.magic[i]=((const u8*)"M4C52001")[i];lease.magic[i]=((const u8*)"M4KLEAS1")[i];}
 for(u32 i=0;i<16;i++){result.nonce[i]=job_nonce[i];lease.nonce[i]=job_nonce[i];}
 for(u32 i=0;i<8;i++)cspi.magic[i]=((const u8*)"M4C52PT1")[i];
 for(u32 i=0;i<16;i++)cspi.nonce[i]=job_nonce[i];cspi.version=1;cspi.load_return=cspi.write_return=-999;
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
 cspi.error=result.error;if(result.error)result.phase=90;
 save_new(JOB_DIR "/cspi",&cspi,sizeof(cspi),0600);
 save_new(JOB_DIR "/result",&result,sizeof(result),0600);
 /* Always allow acknowledgement/cleanup, including rejected/unknown loads.
    Cleanup never removes a kernel module or frees its resident page. */
 int acknowledged=0;i64 begin=now();for(u32 i=0;i<601;i++) {
  i64 n=read_all(JOB_DIR "/ack",command,sizeof(command));
  if(n==32&&same(command,(const u8*)"M4CACK01",8)&&same(command+8,job_nonce,16)&&*(u64*)(command+24)==1){acknowledged=1;break;}
  i64 t=now();if(begin<0||t<begin||t-begin>=60)break;pause_poll();
 }
 if(acknowledged) {
  for(u32 i=0;i<status_index;i++){char path[128];status_name(path,i);cleanup(path);}
  cleanup(JOB_DIR "/load_intent");cleanup(JOB_DIR "/submit_intent");cleanup(JOB_DIR "/cspi");cleanup(JOB_DIR "/start");cleanup(JOB_DIR "/ack");
 } else if(!result.cleanup)result.cleanup=-110;
 /* No ACK: keep all raw states/intents for recovery until tmpfs disappears.
    Neither ACK nor its timeout touches kernel/DMA resources. */
 result.phase=5;result.error=result.cleanup;save_new(JOB_DIR "/cleaned",&result,sizeof(result),0600);exit_child(result.error?1:0);
}
__attribute__((naked,noreturn,visibility("default"))) void _start(void) {
 __asm__ volatile("mov x0,sp\nbl cspi52_main\nmov x0,#127\nmov x8,#94\nsvc #0");
}
