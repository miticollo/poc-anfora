let resolver: ApiResolver | null = null;
try {
    resolver = new ApiResolver("swift" as ApiResolverType);
} catch (e: any) {
    throw new Error("Swift runtime is not available");
}

if (resolver !== null) {
    // Tested on iOS 16.3.1

    /*
     * Frida 16.1.5 introduces a brand new ApiResolver for Swift:
     * https://frida.re/news/2023/11/04/frida-16-1-5-released/#swift
     *
     * Demangling no more required!
     */
    const listener = Interceptor.attach(resolver.enumerateMatches('functions:*GRDB*!*usePassphrase(Foundation.Data)*')[0].address, {
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