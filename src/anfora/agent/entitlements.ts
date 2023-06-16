import {dictFromBytes} from "./lib/dict.js";

const LIBSYSTEM_KERNEL_PATH: string = '/usr/lib/system/libsystem_kernel.dylib';

const CS_OPS_ENTITLEMENTS_BLOB: number = 7;

const csops = new SystemFunction(
    Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'csops'),
    'int',
    ['int', 'int', 'pointer', 'ulong']
)

// struct csheader {
//   uint32_t magic;
//   uint32_t length;
// };

const SIZE_OF_CSHEADER = 8
const ERANGE = 34
const csheader: NativePointer = Memory.alloc(SIZE_OF_CSHEADER)

const ntohl = (val: number) => ((val & 0xFF) << 24)
    | ((val & 0xFF00) << 8)
    | ((val >> 8) & 0xFF00)
    | ((val >> 24) & 0xFF);

function getBlob(pid: number, op: number) {
    const rcent = csops(pid, op, csheader, SIZE_OF_CSHEADER) as UnixSystemFunctionResult<number>
    if (rcent.value == -1 && rcent.errno == ERANGE) {
        const length = ntohl(csheader.add(4).readU32());
        const content: NativePointer = Memory.alloc(length);
        if (csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, content, length).value === 0)
            return dictFromBytes(content.add(SIZE_OF_CSHEADER), length - SIZE_OF_CSHEADER);
    }
    return null;
}

export function getMyEntitlements() {
    return getBlob(Process.id, CS_OPS_ENTITLEMENTS_BLOB);
}