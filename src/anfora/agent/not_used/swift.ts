/*
 * Find the path of the framework into target app
 */
const GRDB_PATH: string = Process.enumerateModules().find((x: Module): boolean => x.name === "GRDB")!.path;

declare let Swift: any;

if (Swift.available) {
    // Tested on iOS 14.4.2 and iOS 15.1b1.
    const mangled: string = "$s4GRDB8DatabaseC13usePassphraseyy10Foundation4DataVKF";
    const demangled: NativePointer = Swift.api.swift_demangle(Memory.allocUtf8String(mangled), mangled.length, NULL, NULL, 0);
    console.log(`Function hooked: ${demangled.readUtf8String()}`);

    const listener = Interceptor.attach(Module.getExportByName(GRDB_PATH, mangled), {
        /**
         * @see https://github.com/neil-wu/FridaHookSwiftAlamofire/blob/master/frida-agent/agent/SDSwiftDataStorage.ts
         */
        onEnter(args: InvocationArguments) {
            /*
             * Create a JavaScript Object that represents a SwiftObject.
             *
             * It's highly likely that you will need to adjust the index of `args`.
             * For example, when Swift strings are passed to a function, they can be passed in two ways:
             * - on the stack if the size is less than 16 bytes
             * - on the heap if the size is greater than 16 bytes.
             *
             * If the string is less than 16 bytes, it will be placed in args[0] and args[1], on arm64.
             * If the string is greater than 16 bytes,
             * inside args[0], we will have information about the string size in the LSB
             * (Least Significant Byte), and args[1] will hold the pointer to the Swift.String structure.
             *
             * The Swift.String structure consists of a 32-byte header, followed by the raw string.
             */
             // const obj = new Swift.Object(args[1]);

            /*
             * Retrieve a descriptor from the newly created object.
             */
             // const descriptor = obj.$metadata.getDescription();

            /*
             * With the descriptor, you can determine the classname of `obj` and the name of the module to which the class belongs.
             * These two names can be utilized to list all fields of `obj`.
             * The fields are listed in the same order they are stored in memory.
             */
             // console.log(JSON.stringify(Swift.modules[descriptor.getModuleContext().name].classes[descriptor.name].$fields, null, 4));

            /*
             * Now, let's examine a 2 KiB (= 2048 bits = 8 bits * 256) hexdump starting from `obj.handle` + 16 bytes.
             * We skip 16 bytes because we ignore [`isa`](https://github.com/TannerJin/Swift-MemoryLayout/blob/d8a724d1b41161f0c7c5414717526dbaa7c20867/Swift/Class.swift#L73-L102)
             * and [`refCount`](https://github.com/TannerJin/Swift-MemoryLayout/blob/d8a724d1b41161f0c7c5414717526dbaa7c20867/Swift/Class.swift#L12-L49).
             * It's important to note that a Swift class that is a subclass of NSObject is compatible with ObjC; otherwise, it's not.
             * Similarly, an ObjC object also has an `isa`.
             *
             * Examining the hexdump, we can find a field/property every `Process.pointerSize`.
             */
             // console.log(obj.handle.add(16).readByteArray(256));

            const fieldRecordBuffer: NativePointer = args[1].add(16);
            console.log(fieldRecordBuffer.readPointer().readCString(fieldRecordBuffer.add(8).readU8()));
            listener.detach();
        },
    });
}