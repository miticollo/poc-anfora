/*
 * The main different between this example and 'non_exported_function' is the usage of DebugSymbol.getFunctionByName.
 * You can use this function if you want to use/intercept a named function. While the other solution is good when the
 * function doesn't have an export name.
 *
 * There is only one drawback: the performance. The first time you use DebugSymbol.getFunctionByName is a bit slow.
 * To improve lookup, look here: https://t.me/fridadotre/135901
 */

Interceptor.attach(DebugSymbol.getFunctionByName('TCCResetInternalWithConnection'), {
    onEnter(args): void {
        console.log(`TCCResetInternalWithConnection(${args[0].readLong()},"${args[1].readUtf8String()}", ${new ObjC.Object(args[2])}, NULL, NULL);`);
    },
    onLeave(retval): void {
        console.log(`TCCResetInternalWithConnection returns ${retval}`);
    }
});

const TCCResetInternal = new NativeFunction(
    DebugSymbol.getFunctionByName('TCCResetInternal'),
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
