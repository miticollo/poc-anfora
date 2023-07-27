const GRDB_PATH: string = Process.enumerateModules().find((x: Module): boolean => x.name === "GRDB")!.path;

declare let Swift: any;

if (Swift.available) {
    // Tested on iOS 14.4.2. and iOS 15.1b1.
    const mangled: string = "$s4GRDB8DatabaseC13usePassphraseyy10Foundation4DataVKF";
    const demangled: NativePointer = Swift.api.swift_demangle(Memory.allocUtf8String(mangled), mangled.length, NULL, NULL, 0);
    console.log(`Function hooked: ${demangled.readUtf8String()}`);

    const listener = Interceptor.attach(Module.getExportByName(GRDB_PATH, mangled), {
        onEnter(args) {
            listener.detach();
        },
    });
}