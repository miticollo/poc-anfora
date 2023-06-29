const GRDB_PATH: string = Process.enumerateModules().find((x: Module): boolean => x.name === "GRDB")!.path;

Interceptor.attach(Module.getExportByName(GRDB_PATH, "$s4GRDB8DatabaseC13usePassphraseyy10Foundation4DataVKF"), {
    onEnter(): void {

    }
});
