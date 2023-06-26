import {dictFromNSDict} from "./dict.js";

export function hookKeychain(): void {
    const SECURITY_PATH: string = '/System/Library/Frameworks/Security.framework/Security';

    enum kSec {
        kSecReturnAttributes = "r_Attributes",
        kSecReturnData = "r_Data",
        kSecReturnRef = "r_Ref",
        kSecMatchLimit = "m_Limit",
        kSecMatchLimitAll = "m_LimitAll",
        kSecClass = "class",
        kSecClassKey = "keys",
        kSecClassIdentity = "idnt",
        kSecClassCertificate = "cert",
        kSecClassGenericPassword = "genp",
        kSecClassInternetPassword = "inet",
        kSecAttrService = "svce",
        kSecAttrAccount = "acct",
        kSecAttrAccessGroup = "agrp",
        kSecAttrLabel = "labl",
        kSecAttrCreationDate = "cdat",
        kSecAttrAccessControl = "accc",
        kSecAttrGeneric = "gena",
        kSecAttrSynchronizable = "sync",
        kSecAttrSynchronizableAny = "syna",
        kSecAttrModificationDate = "mdat",
        kSecAttrServer = "srvr",
        kSecAttrDescription = "desc",
        kSecAttrComment = "icmt",
        kSecAttrCreator = "crtr",
        kSecAttrType = "type",
        kSecAttrScriptCode = "scrp",
        kSecAttrAlias = "alis",
        kSecAttrIsInvisible = "invi",
        kSecAttrIsNegative = "nega",
        kSecAttrHasCustomIcon = "cusi",
        kSecProtectedDataItemAttr = "prot",
        kSecAttrAccessible = "pdmn",
        kSecAttrAccessibleWhenUnlocked = "ak",
        kSecAttrAccessibleAfterFirstUnlock = "ck",
        kSecAttrAccessibleAlways = "dk",
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly = "aku",
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly = "akpu",
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = "cku",
        kSecAttrAccessibleAlwaysThisDeviceOnly = "dku",
        kSecValueData = "v_Data",
    }

    const itemClasses = [
        kSec.kSecClassKey,
        kSec.kSecClassIdentity,
        kSec.kSecClassCertificate,
        kSec.kSecClassGenericPassword,
        kSec.kSecClassInternetPassword,
    ];

    function getKeyByValue(value: string): string {
        const index: number = Object.values(kSec).indexOf(value as unknown as kSec);
        if (index == -1)
            return value;
        return Object.keys(kSec)[index];
    }

    if (Process.findModuleByName(SECURITY_PATH) !== null) {
        Interceptor.attach(Module.getExportByName(SECURITY_PATH, "SecItemAdd"), {
            onEnter(args): void {
                const query = dictFromNSDict(new ObjC.Object(args[0]));
                let data: ArrayBuffer | null;
                if (query['v_Data'] === undefined) data = null;
                else {
                    data = query['v_Data'];
                    delete query['v_Data'];
                }
                send({
                    type: "keychain",
                    op: "SecItemAdd",
                    query: Object.fromEntries(Object.entries(query).map(([k, v]) => [getKeyByValue(k), getKeyByValue(v)])),
                }, data);
            }
        });

        Interceptor.attach(Module.getExportByName(SECURITY_PATH, "SecItemUpdate"), {
            onEnter(args): void {
                const query = dictFromNSDict(new ObjC.Object(args[0]));
                const attributesToUpdate = dictFromNSDict(new ObjC.Object(args[1]));
                let data: ArrayBuffer | null;
                if (attributesToUpdate['v_Data'] === undefined) data = null;
                else {
                    data = attributesToUpdate['v_Data'];
                    delete attributesToUpdate['v_Data'];
                }
                send({
                    type: "keychain",
                    op: "SecItemUpdate",
                    query: Object.fromEntries(Object.entries(query).map(([k, v]) => [getKeyByValue(k), getKeyByValue(v)])),
                    attributesToUpdate: Object.fromEntries(Object.entries(attributesToUpdate).map(([k, v]) => [getKeyByValue(k), getKeyByValue(v)])),
                }, data);
            }
        });

        const SecItemDeleteAddress: NativePointer = Module.getExportByName(SECURITY_PATH, "SecItemDelete");
        const SecItemDelete = new NativeFunction(SecItemDeleteAddress, "pointer", ["pointer"]);

        Interceptor.attach(SecItemDeleteAddress, {
            onEnter(args): void {
                const query = dictFromNSDict(new ObjC.Object(args[0]));
                send({
                    type: "keychain",
                    op: "SecItemDelete",
                    query: Object.fromEntries(Object.entries(query).map(([k, v]) => [getKeyByValue(k), getKeyByValue(v)])),
                });
            }
        });

        rpc.exports.clear = function (): void {
            const searchDictionary = ObjC.classes.NSMutableDictionary.alloc().init();
            searchDictionary.setObject_forKey_(kSec.kSecAttrSynchronizableAny, kSec.kSecAttrSynchronizable);
            itemClasses.forEach((clazz) => {

                // set the class-type we are querying for now & delete
                searchDictionary.setObject_forKey_(clazz, kSec.kSecClass);
                SecItemDelete(searchDictionary);
            });
        }
    }
}