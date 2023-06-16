export function hookNotification(): void {
    const {UNUserNotificationServiceConnection} = ObjC.classes;
    const method = UNUserNotificationServiceConnection['- requestAuthorizationWithOptions:forBundleIdentifier:completionHandler:'];
    Interceptor.attach(method.implementation, {
        onEnter(args): void {
            /*
            * options is a sum of UNAuthorizationOptions. For example
            * UNAuthorizationOptionAlert + UNAuthorizationOptionSound = 0x6 because
            * UNAuthorizationOptionAlert = (1 << 2), while UNAuthorizationOptionSound = (1 << 1).
            */
            const options: number = uint64(args[2].toString()).toNumber();
            const bundleIdentifier = new ObjC.Object(args[3]);
            const blockFunc = args[4].add(16).readPointer();
            const listener = Interceptor.attach(blockFunc, {
                onEnter(): void {
                    console.log(
                        '\nBacktrace:\n\t' +
                        Thread.backtrace(this.context)
                            .map(function (value: NativePointer, index: number, array: NativePointer[]): string {
                                const debugSymbol: DebugSymbol = DebugSymbol.fromAddress(value);
                                return `${debugSymbol.address} ${debugSymbol.moduleName}!${debugSymbol.name}`;
                            }, undefined)
                            .join('\n\t')
                    );
                    send({
                        type: "notification",
                        bundleIdentifier: bundleIdentifier.toString(),
                        options: options,
                    });
                    listener.detach();
                }
            });
        }
    });
}