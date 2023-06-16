/*
 * This example - tested on iOS 16.5 iPhone 8+ - shows how to call and trace a function not exported using Ghidra + frida.
 * In particular, it calls TCCResetInternal and traces TCCResetInternalWithConnection: a function called by previous one.
 *
 * Furthermore, it is based on https://stackoverflow.com/a/68335254.
 */

const ghidraImageBase = 0x1a268a000;
const moduleBaseAddress: NativePointer = Module.getBaseAddress("/System/Library/PrivateFrameworks/TCC.framework/TCC");
const functionRealAddress: NativePointer = moduleBaseAddress.add(0x1a26936b4 - ghidraImageBase);
Interceptor.attach(functionRealAddress, {
    onEnter(args): void {
        console.log(`TCCResetInternalWithConnection(${args[0].readLong()},"${args[1].readUtf8String()}", ${new ObjC.Object(args[2])}, NULL, NULL);`);
    },
    onLeave(retval): void {
        console.log(`TCCResetInternalWithConnection returns ${retval}`);
    }
});

const TCCResetInternal = new NativeFunction(
    moduleBaseAddress.add(0x1a26935e8 - ghidraImageBase),
    'int',
    [
        'pointer',
        'pointer',
        'pointer',
        'pointer',
    ]
);
TCCResetInternal(
    Memory.allocUtf8String("TCCAccessResetInternal"),
    ObjC.classes.NSString.stringWithString_("kTCCServiceAll"),
    NULL,
    NULL
);