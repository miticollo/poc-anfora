/*
 * Original work: https://juejin.cn/post/6895583288451465230
 *
 * See also:
 * - https://gist.github.com/wiggin15/0a4c51b5bc6c52e6e31e2234f88558ab
 * - https://gmpy.dev/#removal-of-process-memory-maps-on-osx
 * - https://stackoverflow.com/a/74710092
 */

const LIBPROC_PATH: string = '/usr/lib/libproc.dylib';

const code: string = `#include <glib.h>
#include <stdio.h>

typedef int                     __int32_t;
typedef __int32_t       __darwin_pid_t;         /* [???] process and group IDs */
typedef __darwin_pid_t        pid_t;

#define PATH_MAX                 1024   /* max bytes in pathname */

typedef uint32_t vm32_object_id_t;
typedef unsigned long long vm_object_id_t;
typedef int vm_behavior_t;
typedef int boolean_t;
typedef int vm_prot_t;
typedef unsigned int            vm_inherit_t;   /* might want to change this */
typedef unsigned long long      memory_object_offset_t;

struct vm_region_submap_info_64 {
    vm_prot_t               protection;     /* present access protection */
    vm_prot_t               max_protection; /* max avail through vm_prot */
    vm_inherit_t            inheritance;/* behavior of map/obj on fork */
    memory_object_offset_t  offset;         /* offset into object/map */
    unsigned int            user_tag;       /* user tag on map entry */
    unsigned int            pages_resident; /* only valid for objects */
    unsigned int            pages_shared_now_private; /* only for objects */
    unsigned int            pages_swapped_out; /* only for objects */
    unsigned int            pages_dirtied;   /* only for objects */
    unsigned int            ref_count;       /* obj/map mappers, etc */
    unsigned short          shadow_depth;   /* only for obj */
    unsigned char           external_pager;  /* only for obj */
    unsigned char           share_mode;     /* see enumeration */
    boolean_t               is_submap;      /* submap vs obj */
    vm_behavior_t           behavior;       /* access behavior hint */
    vm32_object_id_t        object_id;      /* obj/map name, not a handle */
    unsigned short          user_wired_count;
    unsigned int            pages_reusable;
    vm_object_id_t          object_id_full;
};

typedef unsigned int            __darwin_natural_t;
typedef __darwin_natural_t      natural_t;
typedef natural_t mach_msg_type_number_t;
typedef struct vm_region_submap_info_64          vm_region_submap_info_data_64_t;

#define VM_REGION_SUBMAP_INFO_V2_SIZE (sizeof (vm_region_submap_info_data_64_t))
#define VM_REGION_SUBMAP_INFO_V2_COUNT_64 ((mach_msg_type_number_t) (VM_REGION_SUBMAP_INFO_V2_SIZE / sizeof (natural_t)))
#define VM_REGION_SUBMAP_INFO_COUNT_64          VM_REGION_SUBMAP_INFO_V2_COUNT_64

typedef int kern_return_t;
#define KERN_SUCCESS                    0
#define KERN_INVALID_ADDRESS            1
typedef guintptr vm_offset_t;
typedef guintptr vm_size_t;
typedef vm_offset_t vm_address_t;

typedef int *vm_region_recurse_info_t;
typedef guint mach_port_t;
typedef mach_port_t vm_map_read_t;

typedef int *vm_region_info_64_t;

extern pid_t getpid(void);
extern kern_return_t vm_region_recurse_64(vm_map_read_t target_task, vm_address_t *address, vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt);
extern void my_printf(uint32_t, uint32_t, uint32_t, const gchar *);
extern int proc_regionfilename(int pid, uint64_t address, void * buffer, uint32_t buffersize);

extern mach_port_t selfTask;

int
main (void) {
    kern_return_t krc = KERN_SUCCESS;
    vm_address_t address = 0;
    vm_size_t size = 0;
    uint32_t depth = 1;
    pid_t pid = getpid();
    char buf[PATH_MAX];

    while (1) {
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        krc = vm_region_recurse_64(selfTask, &address, &size, &depth, (vm_region_info_64_t)&info, &count);
        if (krc == KERN_INVALID_ADDRESS) {
            break;
        }
        if (info.is_submap) {
            depth++;
        } else {
            //do stuff
            proc_regionfilename(pid, address, buf, sizeof(buf));
            my_printf((uint32_t)address, (uint32_t)(address+size), depth, buf);
            address += size;
        }
    }

    return 0;
}`;

const my_printf = new NativeCallback(
    function (address: number, inc: number, depth: number, pathPtr: NativePointer): void {
        const path: string = pathPtr.readUtf8String()!;
        console.log(`Found VM Region: ${address.toString(16).padStart(8, '0')} to ${inc.toString(16).padStart(8, '0')} (depth=${depth}) user_tag: name:${path}`);
    },
    'void', ['uint32', 'uint32', 'uint32', 'pointer']
);

const selfTask = Memory.alloc(4);
selfTask.writeU32(Module.getExportByName(null, 'mach_task_self_').readU32());

const cm: CModule = new CModule(code, {
    getpid: Module.getExportByName(null, 'getpid'),
    vm_region_recurse_64: Module.getExportByName(null, 'vm_region_recurse_64'),
    proc_regionfilename: Module.getExportByName(LIBPROC_PATH, 'proc_regionfilename'),
    selfTask,
    my_printf,
});

rpc.exports = {
    mmap(): void {
        new NativeFunction(cm.main, 'int', [])();
    }
}
