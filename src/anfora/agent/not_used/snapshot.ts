/*
 * An example of CModule in frida. This approach can't be used because there are no daemons that have
 * snaputils entitlements (https://github.com/ProcursusTeam/Procursus/blob/main/build_misc/entitlements/snaputil.xml).
 * In particular, two things are required:
 * - a rooted process and
 * - com.apple.private.vfs.snapshot
 */

const code: string = `#define O_RDONLY 0x0

typedef unsigned int uint32_t;

extern int open(const char *path, int oflag, ...);
extern int fs_snapshot_create(int dirfd, const char * name, uint32_t flags);
extern int close(int fildes);

int
do_create(const char *vol, const char *snap)
{
	int dirfd = open(vol, O_RDONLY, 0);
	
	int ret = fs_snapshot_create(dirfd, snap, 0);
	close(dirfd);
	return (ret);
}
`;

const cm: CModule = new CModule(code, {
    open: Module.getExportByName('libSystem.B.dylib', 'open'),
    close: Module.getExportByName('libSystem.B.dylib', 'close'),
    fs_snapshot_create: Module.getExportByName(null, 'fs_snapshot_create'),
});
const do_create = new NativeFunction(cm.do_create, 'int', ['pointer', 'pointer']);
do_create(Memory.allocUtf8String('/var'), Memory.allocUtf8String('anfora'));