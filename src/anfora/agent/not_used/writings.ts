const LIBSYSTEM_KERNEL_PATH: string = '/usr/lib/system/libsystem_kernel.dylib';
const LIBPROC_PATH: string = '/usr/lib/libproc.dylib';

const code: string = `#include <glib.h>

typedef int                     __int32_t;
typedef unsigned int            __uint32_t;
typedef long long               __int64_t;

typedef struct fsid { int32_t val[2]; } fsid_t; /* file system id type */

typedef __int32_t       __darwin_pid_t;         /* [???] process and group IDs */
typedef __darwin_pid_t        pid_t;

typedef __uint32_t      __darwin_gid_t;         /* [???] process and group IDs */
typedef __darwin_gid_t  gid_t;

typedef __uint32_t      __darwin_uid_t;         /* [???] user IDs */
typedef __darwin_uid_t        uid_t;

typedef __int64_t       __darwin_off_t;         /* [???] Used for file sizes */
typedef __darwin_off_t          off_t;

#define PATH_MAX                 1024   /* max bytes in pathname */
#define MAXPATHLEN      PATH_MAX

struct proc_fileinfo {
    uint32_t                fi_openflags;
    uint32_t                fi_status;
    off_t                   fi_offset;
    int32_t                 fi_type;
    uint32_t                fi_guardflags;
};

struct vinfo_stat {
    uint32_t        vst_dev;        /* [XSI] ID of device containing file */
    uint16_t        vst_mode;       /* [XSI] Mode of file (see below) */
    uint16_t        vst_nlink;      /* [XSI] Number of hard links */
    uint64_t        vst_ino;        /* [XSI] File serial number */
    uid_t           vst_uid;        /* [XSI] User ID of the file */
    gid_t           vst_gid;        /* [XSI] Group ID of the file */
    int64_t         vst_atime;      /* [XSI] Time of last access */
    int64_t         vst_atimensec;  /* nsec of last access */
    int64_t         vst_mtime;      /* [XSI] Last data modification time */
    int64_t         vst_mtimensec;  /* last data modification nsec */
    int64_t         vst_ctime;      /* [XSI] Time of last status change */
    int64_t         vst_ctimensec;  /* nsec of last status change */
    int64_t         vst_birthtime;  /*  File creation time(birth)  */
    int64_t         vst_birthtimensec;      /* nsec of File creation time */
    off_t           vst_size;       /* [XSI] file size, in bytes */
    int64_t         vst_blocks;     /* [XSI] blocks allocated for file */
    int32_t         vst_blksize;    /* [XSI] optimal blocksize for I/O */
    uint32_t        vst_flags;      /* user defined flags for file */
    uint32_t        vst_gen;        /* file generation number */
    uint32_t        vst_rdev;       /* [XSI] Device ID */
    int64_t         vst_qspare[2];  /* RESERVED: DO NOT USE! */
};

struct vnode_info {
    struct vinfo_stat       vi_stat;
    int                     vi_type;
    int                     vi_pad;
    fsid_t                  vi_fsid;
};

struct vnode_info_path {
    struct vnode_info       vip_vi;
    char                    vip_path[MAXPATHLEN];   /* tail end of it  */
};

struct vnode_fdinfo {
    struct proc_fileinfo    pfi;
    struct vnode_info       pvi;
};

struct vnode_fdinfowithpath {
    struct proc_fileinfo    pfi;
    struct vnode_info_path  pvip;
};

struct proc_fdinfo {
    int32_t                 proc_fd;
    uint32_t                proc_fdtype;
};

#define PROC_PIDFDVNODEPATHINFO         2

extern int proc_pidfdinfo(int pid, int fd, int flavor, void * buffer, int buffersize);
extern pid_t getpid(void);

gchar * 
get_path(int fd) {
    struct vnode_fdinfowithpath fdpath = {};
        int bufferSize = proc_pidfdinfo(getpid(), fd, PROC_PIDFDVNODEPATHINFO, &fdpath, sizeof(struct vnode_fdinfowithpath));
    if (bufferSize >= 0 && bufferSize >= sizeof(struct vnode_fdinfo)) return fdpath.pvip.vip_path;
    return NULL;
}`;

const m: CModule = new CModule(code, {
    proc_pidfdinfo: Module.getExportByName(LIBPROC_PATH, 'proc_pidfdinfo'),
    getpid: Module.getExportByName(null, 'getpid'),
});

const paths: Set<string> = new Set();

Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'write'), {
    onEnter(args): void {
        this.fd = args[0].toInt32();
    },
    onLeave(retval): void {
        const n: number = retval.toInt32();
        if (n === -1)
            return;

        const pathPtr: NativePointer = new NativeFunction(m.get_path, 'pointer', ['int'])(this.fd);
        if (!pathPtr.isNull()) {
            const path: string = pathPtr.readUtf8String()!;
            if (!paths.has(path)) {
                send({
                    type: "write",
                    path: path,
                });
                paths.add(path);
            }
        }
    }
});