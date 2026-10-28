/* Fixed-path inventory only. Derived helpers: Erlla MIT upstream.
 * No block open, ioctl, mount, pwrite, firmware or settings write.
 * Output and handshake files are restricted to nonce-scoped checked tmpfs.
 */
#define _start unused_lifecycle_start
#define worker_main unused_lifecycle_main
#include "lifecycle_worker.c"
#undef worker_main
#undef _start
static u8 inventory_buffer[524289];
#ifndef INVENTORY_DIAGNOSTICS
#ifdef INVENTORY_KERNEL_LEASE_STATUS
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo",
    "/sys/module/m4btl_lease_01/initstate",
    "/sys/module/m4btl_lease_01/parameters/status",
    "/sys/module/m4btl_lease_01/parameters/nonce",
    "/sys/module/m4btl_lease_01/parameters/state",
    "/sys/module/m4btl_lease_01/parameters/bytes",
    "/sys/module/m4btl_lease_01/parameters/phys",
    "/proc/sys/kernel/random/boot_id", "/proc/uptime"
};
#elif defined(INVENTORY_MODULE_POLICY)
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo",
    "/proc/sys/kernel/modules_disabled", "/sys/module/module/parameters/sig_enforce",
    "/proc/sys/kernel/kptr_restrict", "/proc/modules", "/proc/self/status",
    "/sys/module/module/parameters", "/sys/module", "/proc/sys/kernel"
};
#elif defined(INVENTORY_DMM_METADATA)
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo",
    "/proc/udm/dmm_rule", "/proc/udm/dmm_extents", "/proc/udm/dmm_units",
    "/proc/udm/dmm_units2", "/proc/udm/dmm_reserve", "/proc/udm/dmm_info",
    "/proc/self/status", "/proc/uptime"
};
#elif defined(INVENTORY_MEMORY_ACCESS_METADATA)
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo", "/proc/self/status",
    "/sys/module/mmap/parameters/debug", "/sys/module/adrs_conv/parameters/debug",
    "/proc/udm/gpio", "/proc/udm/gpio",
    "/sys/module/mmap/parameters", "/sys/module/adrs_conv/parameters",
    "/cp"
};
#elif defined(INVENTORY_BACKUP_CONFIG)
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo",
    "/sys/module/backup/parameters/Backup_pri_file",
    "/sys/module/backup/parameters/Backup_sec_file",
    "/sys/module/backup/parameters/Backup_save",
    "/sys/module/backup/parameters/Backup_load", "/proc/uptime",
    "/sys/module/backup/parameters", "/sys/module/backup",
    "/sys/module/pcieatu/parameters"
};
#elif defined(INVENTORY_MEMORY_MAPS)
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo", "/proc/iomem",
    "/proc/interrupts", "/proc/meminfo", "/proc/cmdline", "/proc/cpuinfo",
    "/sys/devices/platform", "/proc/udm", "/sys/bus/spi/devices"
};
#else
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo", "/etc/fstab",
    "/proc/mtd", "/proc/devices", "/proc/cmdline", "/proc/cpuinfo",
    "/dev", "/sys/class/block", "/sys/class/mtd"
};
#endif
#else
#ifdef INVENTORY_LIVE_LOGS
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo", "/proc/klog",
    "/proc/osal/uipc", "/proc/udm/dmm_log", "/proc/cmdline", "/proc/uptime",
    "/proc", "/sys/fs/pstore", "/proc/udm"
};
static i64 read_live_snapshot(const char*path) {
    /* Only the fixed proc nodes above use NONBLOCK. A snapshot may end at
       EAGAIN or the capacity bound; neither is proof of complete log history. */
    i64 fd=op(path,A64_READ|00004000,0);if(fd<0)return fd;
    u64 done=0;i64 result=-75;const u64 cap=sizeof(inventory_buffer)-1;
    for(u32 calls=0;calls<256;calls++) {
        if(done==cap){result=(i64)done;break;}
        i64 n=sc(63,fd,(i64)(inventory_buffer+done),cap-done,0,0,0);
        if(n==-4)continue;
        if(n==0||n==-11){result=(i64)done;break;}
        if(n<0){result=n;break;}
        if((u64)n>cap-done){result=-5;break;}done+=(u64)n;
    }
    i64 c=cl(fd);return c?c:result;
}
#else
static const char *files[] = {
    "/proc/version", "/proc/partitions", "/proc/self/mountinfo", "/proc/last_kmsg",
    "/proc/uptime", "/proc/meminfo", "/proc/cmdline", "/proc/sys/kernel/tainted",
    "/log", "/sys/fs/pstore", "/var/log"
};
#endif
struct LogInfo {char name[96];i64 error;u64 size,offset,bytes;};
_Static_assert(sizeof(struct LogInfo)==128,"log metadata ABI");
static struct LogInfo logs[16];
static u8 log_buffer[131072],log_stat[128];
static u32 log_count=0;
static void log_name(char*out,u32 index) {
    const char*base=JOB_DIR "/log";u32 n=0;while(base[n]){out[n]=base[n];n++;}
    out[n++]=(char)('0'+index/10);out[n++]=(char)('0'+index%10);out[n]=0;
}
static i64 capture_log_tail(u32 index) {
    char path[128];u32 n=0;const char*root="/log/";
    for(u32 i=0;root[i];i++)path[n++]=root[i];
    for(u32 i=0;logs[index].name[i];i++)path[n++]=logs[index].name[i];path[n]=0;
    i64 fd=op(path,A64_READ,0);if(fd<0)return fd;
    i64 r=sc(80,fd,(i64)log_stat,0,0,0,0);
    if(!r&&(*(u32*)(log_stat+16)&0170000)!=0100000)r=-22;
    if(!r) {
        i64 size=*(i64*)(log_stat+48);if(size<0)r=-22;
        else {
            logs[index].size=(u64)size;
            u64 length=(u64)size;if(length>sizeof(log_buffer))length=sizeof(log_buffer);
            logs[index].offset=(u64)size-length;
            u64 done=0;u32 calls=0;
            while(done<length&&++calls<=4096) {
                i64 got=sc(67,fd,(i64)(log_buffer+done),length-done,logs[index].offset+done,0,0);
                if(got==-4)continue;
                if(got<=0||(u64)got>length-done){r=got<0?got:-5;break;}done+=(u64)got;
            }
            if(!r&&done!=length)r=-11;
            if(!r)logs[index].bytes=length;
        }
    }
    i64 c=cl(fd);if(!r&&c)r=c;if(r)return r;
    log_name(path,index);return save_new(path,log_buffer,logs[index].bytes,0600);
}
static i64 capture_log_tails(u64 length) {
    for(u64 at=0;at<length&&log_count<16;) {
        if(at+20>length)return -22;
        u64 size=inventory_buffer[at+16]+((u64)inventory_buffer[at+17]<<8);
        if(size<20||at+size>length)return -22;
        const u8*name=inventory_buffer+at+19;u64 n=0;int valid=inventory_buffer[at+18]==8;
        while(19+n<size&&name[n]) {
            u8 x=name[n];if(n>=95||!((x>='a'&&x<='z')||(x>='A'&&x<='Z')||(x>='0'&&x<='9')||x=='.'||x=='_'||x=='-'))valid=0;
            n++;
        }
        if(!n||19+n>=size||name[0]=='.')valid=0;
        if(valid) {
            u32 i=log_count++;for(u64 j=0;j<n;j++)logs[i].name[j]=(char)name[j];logs[i].name[n]=0;
            logs[i].error=capture_log_tail(i);
        }
        at+=size;
    }
    return save_new(JOB_DIR "/logindex",logs,sizeof(logs),0600);
}
#endif
static i64 statuses[11];
static void clean_file(const char *path) {
    i64 r=unlink(path);if(r&&r!=-2&&!result.cleanup)result.cleanup=r;
}
static void output_name(char *out, u32 index) {
    const char *base=JOB_DIR "/f";u32 n=0;
    while(base[n]) {out[n]=base[n];n++;}
    out[n++]=(char)('0'+index/10);out[n++]=(char)('0'+index%10);out[n]=0;
}
static i64 read_directory(const char *path) {
    i64 fd=op(path,A64_DIRECTORY,0);if(fd<0)return fd;
    u64 done=0;i64 r=-75;
    for(u32 calls=0;calls<128;calls++) {
        if(done>=sizeof(inventory_buffer))break;
        i64 n=sc(61,fd,(i64)(inventory_buffer+done),sizeof(inventory_buffer)-done,0,0,0);
        if(n==-4)continue;
        if(n<0) {r=n;break;}
        if(!n) {r=(i64)done;break;}
        if((u64)n>sizeof(inventory_buffer)-done) {r=-5;break;}
        done+=(u64)n;
    }
    i64 c=cl(fd);return c?c:r;
}
static i64 capture_inventory(void) {
    for(u32 i=0;i<11;i++)statuses[i]=-999;
    for(u32 i=0;i<11;i++) {
        i64 n;
#ifdef INVENTORY_LIVE_LOGS
        if(i>=3&&i<=5)n=read_live_snapshot(files[i]);
        else
#endif
#if defined(INVENTORY_DMM_METADATA) || defined(INVENTORY_KERNEL_LEASE_STATUS)
        n=read_all(files[i],inventory_buffer,sizeof(inventory_buffer));
#else
        n=i<8?read_all(files[i],inventory_buffer,sizeof(inventory_buffer)):read_directory(files[i]);
#endif
        statuses[i]=n;
        if(n>=0) {char path[128];output_name(path,i);i64 r=save_new(path,inventory_buffer,(u64)n,0600);if(r)return r;}
        /* Only proc/version, partition table and mountinfo are prerequisites.
         * fstab is not required to exist on an embedded product. Retain the
         * exact failing index even when a required proc file is absent. */
        else if(i<3) {
            i64 saved=save_new(JOB_DIR "/statuses",statuses,sizeof(statuses),0600);
            return saved?saved:n;
        }
#if defined(INVENTORY_DIAGNOSTICS) && !defined(INVENTORY_LIVE_LOGS)
        if(i==8&&n>=0){i64 r=capture_log_tails((u64)n);if(r)return r;}
#endif
    }
    return save_new(JOB_DIR "/statuses",statuses,sizeof(statuses),0600);
}
void inventory_main(u64 *stack) {
    for(i64 fd=0;fd<4096;fd++)cl(fd);
    for(u32 i=0;i<8;i++)result.magic[i]=((const u8*)"M4INV001")[i];
    for(u32 i=0;i<16;i++)result.nonce[i]=job_nonce[i];
    result.version=1;result.phase=1;result.euid=sc(175,0,0,0,0,0,0);
    result.pid=sc(172,0,0,0,0,0,0);result.ppid=sc(173,0,0,0,0,0,0);
    if(stack[0]!=2) {result.error=-22;goto finished;}
    const char *p=(const char*)stack[2];u64 value=0;u32 digits=0;
    while(p[digits] && digits<10) {
        if(p[digits]<'0'||p[digits]>'9') {result.error=-22;goto finished;}
        value=value*10+(u64)(p[digits++]-'0');
    }
    if(!digits||p[digits]||value<=1||value>0x7fffffffUL) {result.error=-22;goto finished;}
    result.loader_pid=value;
    for(u32 i=0;result.ppid!=1&&i<100;i++) {
        i64 ts[2]={0,1000000};sc(101,(i64)ts,0,0,0,0,0);result.ppid=sc(173,0,0,0,0,0,0);
    }
    if(result.ppid!=1||result.euid) {result.error=-13;goto finished;}
    result.cleanup=unlink(JOB_DIR "/worker");if(result.cleanup) {result.error=result.cleanup;goto finished;}
    result.error=tmpfs(&fs);if(result.error)goto finished;
    result.fs_available=fs.bsize*fs.bavail;
    result.error=verify_inherited_closed();if(result.error)goto finished;
    result.error=save_new(JOB_DIR "/ready",&result,sizeof(result),0600);if(result.error)goto finished;
    result.phase=2;result.error=wait_start();if(result.error)goto finished;
    result.phase=3;result.error=inspect_loader();if(result.error)goto finished;
    result.error=capture_inventory();if(!result.error)result.phase=4;
finished:
    if(result.error)result.phase=90;
    save_new(JOB_DIR "/result",&result,sizeof(result),0600);
    if(!result.error) {
        i64 begin=now();
        for(u32 i=0;i<601;i++) {
            i64 n=read_all(JOB_DIR "/ack",command,sizeof(command));
            if(n==32&&same(command,(const u8*)"M4ACK001",8)&&same(command+8,job_nonce,16)&&*(u64*)(command+24)==1)break;
            i64 t=now();if(begin<0||t<begin||t-begin>=60)break;pause_poll();
        }
        for(u32 i=0;i<11;i++)if(statuses[i]>=0) {char path[128];output_name(path,i);clean_file(path);}
        clean_file(JOB_DIR "/statuses");clean_file(JOB_DIR "/ack");
#ifdef INVENTORY_DIAGNOSTICS
        for(u32 i=0;i<log_count;i++){char path[128];log_name(path,i);clean_file(path);}
        clean_file(JOB_DIR "/logindex");
#endif
    }
    if(!result.error&&result.cleanup)result.error=result.cleanup;
    result.phase=5;save_new(JOB_DIR "/cleaned",&result,sizeof(result),0600);
    exit_child(result.error?1:0);
}
__attribute__((naked,noreturn,visibility("default"))) void _start(void) {
    __asm__ volatile("mov x0,sp\nbl inventory_main\nmov x0,#127\nmov x8,#94\nsvc #0");
}
