/* Fixed-target current RAM observation. This never writes process memory and
 * does not establish continuity with the original patch worker's closed mm.
 */
#include "linux_a64.h"
#include "job.h"

struct CurrentReadResult {
    u8 magic[8],nonce[16],patch_nonce[16],spec_sha256[32];
    i64 values[FIELD_COUNT];
};
_Static_assert(sizeof(struct CurrentReadResult)==72+8*FIELD_COUNT,"current read wire ABI");
static struct CurrentReadResult wr;
#define V(name) wr.values[F_##name]
static struct Fs fs;
static u8 maps[524289],statbuf[4096],buffer[64],command[49];
struct Target {
    i64 pid,fd,base,addr;
    u64 patch_offset,anchor_offset,anchor_bytes,version_offset,version_bytes;
    const char *name;
    const u8 *anchor;
    u64 row_bytes;
    u8 row[512];
    i64 maps_before_bytes,maps_after_bytes,start_before,start_after,word_before,word_after;
    i64 version_before,version_after,anchor_before_status,anchor_after_status;
    i64 maps_status,stat_status,mem_status,mem_closed;
};
static struct Target lib,app;
static u32 proc_path(char*out,u64 pid,const char*suffix) {
    const char prefix[]="/proc/";u32 n=0;
    for(u32 i=0;i<6;i++)out[n++]=prefix[i];n+=decimal(out+n,pid);
    for(u32 i=0;suffix[i];i++)out[n++]=suffix[i];out[n]=0;return n;
}
static i64 monotonic_ns(void) {
    i64 ts[2];i64 r=sc(113,1,(i64)ts,0,0,0,0);
    if(r)return r;
    if(ts[0]<0 || ts[0]>9223372035LL || ts[1]<0 || ts[1]>=1000000000)return -75;
    return ts[0]*1000000000+ts[1];
}
static i64 wait_start(void) {
    i64 begin=monotonic_ns();if(begin<0)return begin;
    for(u32 poll=0;poll<=1200;poll++) {
        i64 n=read_all(JOB_DIR "/start",command,sizeof(command));
        if(n>0) {
            if(n!=48 || !same(command,(const u8*)"M4RSTART",8) ||
               !same(command+8,job_nonce,16) || !same(command+24,patch_nonce,16))return -84;
            u64 version=0;for(u32 i=0;i<8;i++)version|=(u64)command[40+i]<<(i*8);
            if(version!=1)return -22;
            return unlink(JOB_DIR "/start");
        }
        if(n<0 && n!=-2)return n;
        i64 now=monotonic_ns();if(now<0)return now;
        if(now<begin || now-begin>=120000000000L)return -110;
        i64 ts[2]={0,100000000};i64 r=sc(101,(i64)ts,0,0,0,0,0);if(r && r!=-4)return r;
    }
    return -110;
}
static i64 hex_at(u64 end,u64*at,u64*out) {
    u64 value=0;u32 digits=0;
    while(*at<end) {
        u8 c=maps[*at];i64 v=(c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:-1;
        if(v<0)break;if(++digits>16)return -22;value=value*16+(u64)v;(*at)++;
    }
    if(!digits || value>0x7fffffffffffffffUL)return -22;*out=value;return 0;
}
static void spaces(u64 end,u64*p){while(*p<end && maps[*p]==' ')(*p)++;}
static i64 select_map(struct Target*t,u64 n,int first) {
    if(!n)return -3;if(maps[n-1]!='\n')return -75;
    u64 at=0,found=0,row_at=0,row_bytes=0;
    while(at<n) {
        u64 end=at;while(end<n && maps[end]!='\n')end++;
        u64 p=at,start=0,stop=0,offset=0;
        if(hex_at(end,&p,&start) || p>=end || maps[p++]!='-' || hex_at(end,&p,&stop) ||
           p>=end || maps[p++]!=' ' || p+4>=end)return -22;
        u64 perms=p;p+=4;if(maps[p++]!=' ')return -22;spaces(end,&p);
        if(hex_at(end,&p,&offset) || p>=end || maps[p++]!=' ')return -22;
        spaces(end,&p);
        for(u32 field=0;field<2;field++) {
            u64 begin=p;while(p<end && maps[p]!=' ')p++;
            if(p==begin)return -22;spaces(end,&p);
        }
        u64 length=0;while(t->name[length])length++;
        if(end-p==9+length && same(maps+p,(const u8*)"/usr/lib/",9) &&
           same(maps+p+9,(const u8*)t->name,length) && maps[perms]=='r' && maps[perms+2]=='x') {
            if(stop<=start || start<offset || t->patch_offset<offset ||
               t->patch_offset+4-offset>stop-start){at=end+1;continue;}
            if(maps[perms+1]!='-' || maps[perms+3]!='p')return -84;
            if(++found>1)return -75;
            if(start-offset!=(u64)t->base || start-offset+t->patch_offset!=(u64)t->addr)return -116;
            if(t->anchor_offset<offset || t->anchor_offset+t->anchor_bytes-offset>stop-start)return -75;
            row_at=at;row_bytes=end-at;if(!row_bytes || row_bytes>sizeof(t->row))return -75;
        }
        at=end+1;
    }
    if(!found)return -3;
    if(first) {
        t->row_bytes=row_bytes;for(u64 i=0;i<row_bytes;i++)t->row[i]=maps[row_at+i];
    } else if(t->row_bytes!=row_bytes || !same(t->row,maps+row_at,row_bytes))return -116;
    return 0;
}
static i64 read_maps(struct Target*t,int first) {
    char path[64];proc_path(path,(u64)t->pid,"/maps");
    i64 n=read_all(path,maps,sizeof(maps));if(n<0)return t->maps_status=n;
    if(first)t->maps_before_bytes=n;else t->maps_after_bytes=n;
    return t->maps_status=select_map(t,(u64)n,first);
}
static i64 read_start_ticks(struct Target*t,i64*out) {
    char path[64];proc_path(path,(u64)t->pid,"/stat");
    i64 n=read_all(path,statbuf,sizeof(statbuf));if(n<0)return t->stat_status=n;
    u64 p=0,pid=0,digits=0,last=0;
    while(p<(u64)n && statbuf[p]>='0' && statbuf[p]<='9') {
        if(++digits>10)return t->stat_status=-22;pid=pid*10+statbuf[p++]-'0';
    }
    if(!digits || pid!=(u64)t->pid || p+2>=(u64)n || statbuf[p++]!=' ' || statbuf[p]!='(')return t->stat_status=-22;
    for(u64 i=p+1;i<(u64)n;i++)if(statbuf[i]==')')last=i;
    if(!last || last+2>=(u64)n || statbuf[last+1]!=' ')return t->stat_status=-22;
    p=last+2;
    for(u32 field=3;field<22;field++) {
        u64 begin=p;while(p<(u64)n && statbuf[p]!=' ' && statbuf[p]!='\n')p++;
        if(p==begin || p>=(u64)n || statbuf[p]!=' ')return t->stat_status=-22;
        while(p<(u64)n && statbuf[p]==' ')p++;
    }
    u64 value=0;digits=0;
    while(p<(u64)n && statbuf[p]>='0' && statbuf[p]<='9') {
        u64 digit=statbuf[p++]-'0';if(value>(0x7fffffffffffffffUL-digit)/10)return t->stat_status=-75;
        value=value*10+digit;digits++;
    }
    if(!digits || !value || p>=(u64)n || (statbuf[p]!=' ' && statbuf[p]!='\n'))return t->stat_status=-22;
    *out=(i64)value;return t->stat_status=0;
}
static i64 pread_exact(struct Target*t,u64 address,u64 count) {
    for(u64 i=0;i<sizeof(buffer);i++)buffer[i]=0;
    for(u32 calls=0;calls<4;calls++) {
        i64 n=sc(67,t->fd,(i64)buffer,count,address,0,0);
        if(n==-4)continue;
        return n==(i64)count?0:(n<0?n:-5);
    }
    return -11;
}
static i64 scalar(u64 count) {u64 value=0;for(u64 i=0;i<count;i++)value|=(u64)buffer[i]<<(8*i);return (i64)value;}
static i64 observe(struct Target*t,int first) {
    i64 r=pread_exact(t,(u64)t->base+t->anchor_offset,t->anchor_bytes);
    if(!r)for(u64 i=0;i<t->anchor_bytes;i++)
        if((i+t->anchor_offset<t->patch_offset || i+t->anchor_offset>=t->patch_offset+4) && buffer[i]!=t->anchor[i]){r=-84;break;}
    if(first)t->anchor_before_status=r;else t->anchor_after_status=r;
    if(r)return r;
    r=pread_exact(t,(u64)t->base+t->version_offset,t->version_bytes);
    i64 version=scalar(t->version_bytes);
    if(first)t->version_before=version;else t->version_after=version;
    if(r)return t->mem_status=r;
    if(version!=(t==&lib?0x0602:0x00060002))return -84;
    r=pread_exact(t,(u64)t->addr,4);i64 word=scalar(4);
    if(first)t->word_before=word;else t->word_after=word;
    return t->mem_status=r;
}
#define COPY(prefix,target,field) V(prefix##_##field)=target.field
#define EXPORT(prefix,target) \
    COPY(prefix,target,maps_before_bytes);COPY(prefix,target,maps_after_bytes); \
    COPY(prefix,target,start_before);COPY(prefix,target,start_after); \
    COPY(prefix,target,word_before);COPY(prefix,target,word_after); \
    COPY(prefix,target,version_before);COPY(prefix,target,version_after); \
    COPY(prefix,target,anchor_before_status);COPY(prefix,target,anchor_after_status); \
    COPY(prefix,target,maps_status);COPY(prefix,target,stat_status); \
    COPY(prefix,target,mem_status);COPY(prefix,target,mem_closed)
static void sync_result(void){EXPORT(lib,lib);EXPORT(app,app);}
static i64 first_pass(struct Target*t,i64 flag) {
    i64 r=read_maps(t,1);if(r)return r;
    r=read_start_ticks(t,&t->start_before);if(r)return r;
    char path[64];proc_path(path,(u64)t->pid,"/mem");
    t->fd=op(path,A64_READ,0);if(t->fd<0)return t->mem_status=t->fd;
    V(flags)|=flag;
    r=read_maps(t,0);if(r)return r;
    return observe(t,1);
}
static i64 second_pass(struct Target*t) {
    i64 r=observe(t,0);if(r)return r;
    r=read_maps(t,0);if(r)return r;
    r=read_start_ticks(t,&t->start_after);if(r)return r;
    if(t->word_before!=t->word_after || t->start_before!=t->start_after ||
       t->maps_before_bytes!=t->maps_after_bytes)return -116;
    return 0;
}
void read_main(u64*stack) {
    i64 close_error=0;
    for(i64 fd=0;fd<4096;fd++){i64 r=cl(fd);if(r && r!=-9 && !close_error)close_error=r;}
    const u8 magic[]="M4IPR001";
    for(u32 i=0;i<8;i++)wr.magic[i]=magic[i];
    for(u32 i=0;i<16;i++){wr.nonce[i]=job_nonce[i];wr.patch_nonce[i]=patch_nonce[i];}
    for(u32 i=0;i<32;i++)wr.spec_sha256[i]=target_spec_sha256[i];
    V(version)=1;V(phase)=1;
    lib=(struct Target){.pid=LIB_PID,.fd=-1,.base=LIB_BASE,.addr=LIB_ADDR,.name="libupdaterufp.so",
        .patch_offset=8016,.anchor_offset=8004,.anchor_bytes=20,.version_offset=152164,.version_bytes=2,.anchor=anchor};
    app=(struct Target){.pid=APP_PID,.fd=-1,.base=APP_BASE,.addr=APP_ADDR,.name="appFw.so",
        .patch_offset=40219336,.anchor_offset=40219316,.anchor_bytes=32,.version_offset=134261208,.version_bytes=4,.anchor=app_anchor};
    V(lib_pid)=lib.pid;V(lib_base_addr)=lib.base;V(lib_target_addr)=lib.addr;
    V(app_pid)=app.pid;V(app_base_addr)=app.base;V(app_target_addr)=app.addr;
    V(euid)=sc(175,0,0,0,0,0,0);V(pid)=sc(172,0,0,0,0,0,0);V(ppid)=sc(173,0,0,0,0,0,0);
    if(stack[0]!=2){V(error)=-22;goto done;}
    const char*p=(const char*)stack[2];u64 loader=0,digits=0;
    while(p[digits] && digits<10){if(p[digits]<'0'||p[digits]>'9'){V(error)=-22;goto done;}loader=loader*10+p[digits++]-'0';}
    if(!digits || p[digits] || loader<=1 || loader>0x7fffffffUL){V(error)=-22;goto done;}
    V(loader_pid)=(i64)loader;
    for(u32 i=0;V(ppid)!=1 && i<100;i++) {
        i64 ts[2]={0,1000000};i64 r=sc(101,(i64)ts,0,0,0,0,0);
        if(r && r!=-4){V(error)=r;goto done;}
        V(ppid)=sc(173,0,0,0,0,0,0);
    }
    V(cleanup)=unlink(JOB_DIR "/worker");
    if(V(euid) || V(ppid)!=1 || V(cleanup) || close_error){V(error)=close_error?close_error:-13;goto done;}
    V(flags)=9;V(error)=tmpfs(&fs);if(V(error))goto done;V(flags)|=4;
    V(error)=save_new(JOB_DIR "/ready",&wr,sizeof(wr),0600);if(V(error))goto done;
    V(phase)=2;V(error)=wait_start();if(V(error))goto done;V(flags)|=16;
    V(phase)=3;V(error)=first_pass(&lib,32);if(V(error))goto done;
    V(error)=first_pass(&app,64);if(V(error))goto done;V(passes)=1;V(flags)|=128;
    V(phase)=4;V(error)=second_pass(&lib);if(V(error))goto done;
    V(error)=second_pass(&app);if(V(error))goto done;V(passes)=2;V(flags)|=512;
    V(phase)=7;
done:
    if(lib.fd>=0){i64 r=cl(lib.fd);lib.fd=-1;if(!r)lib.mem_closed=1;else{if(!lib.mem_status)lib.mem_status=r;if(!V(error))V(error)=r;}}
    if(app.fd>=0){i64 r=cl(app.fd);app.fd=-1;if(!r)app.mem_closed=1;else{if(!app.mem_status)app.mem_status=r;if(!V(error))V(error)=r;}}
    if(lib.mem_closed && app.mem_closed)V(flags)|=256;
    sync_result();if(V(error))V(phase)=90;
    i64 publication=save_new(JOB_DIR "/result.pending",&wr,sizeof(wr),0600);
    if(!publication)publication=sc(276,-100,(i64)(JOB_DIR "/result.pending"),-100,(i64)(JOB_DIR "/result"),1,0);
    exit_child(V(error) || publication?1:0);
}
__attribute__((naked,noreturn,visibility("default"))) void _start(void) {
    __asm__ volatile("mov x0,sp\nbl read_main\nmov x0,#127\nmov x8,#94\nsvc #0");
}
