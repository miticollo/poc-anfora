export function hookContact(): void {
    const processInformationAgent = ObjC.classes.NSProcessInfo.processInfo();        // this is a shared object between processes
    const majorVersion: number = parseInt(processInformationAgent.operatingSystemVersion()[0]);
    let executeSaveRequest: string = majorVersion >= 13 ? '- executeSaveRequest:response:authorizationContext:error:' : '- executeSaveRequest:response:error:';

    const {CNDataMapperContactStore} = ObjC.classes;
    if (CNDataMapperContactStore !== undefined) {                                    // for intents_helper, MTLCompilerService
        Interceptor.attach(CNDataMapperContactStore[executeSaveRequest].implementation, {
            onEnter: function (args): void {
                const saveRequest = new ObjC.Object(args[2]);
                const array = saveRequest.allContacts();
                const count = array.count().valueOf();
                for (let i = 0; i !== count; i++) {
                    const contact = array.objectAtIndex_(i);
                    send({
                        type: "contact",
                        message: contact.$ivars['_internalIdentifier'].UTF8String(),
                    });
                }
            }
        });
    }
}