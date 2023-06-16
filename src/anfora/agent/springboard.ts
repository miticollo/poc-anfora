import {arrayFromNSArray} from "./lib/dict.js";
import {getMyEntitlements} from "./entitlements.js";

const {
    CLLocationManager,
    CNContact,
    NSArray,
    NSString,
    CNContactStore,
    CNSaveRequest,
    LSApplicationProxy,
    FBSSystemService,
    RadiosPreferences,
    BrightnessSystemClient,
    AMSSignOutTask,
    NSProcessInfo,
    BBDataProviderConnection,
    BBServer,
    NEConfigurationManager,
} = ObjC.classes;
const kCFAllocatorDefault: NativePointer = Module.getExportByName('CoreFoundation', 'kCFAllocatorDefault').readPointer();
const CFBundleCreate = new NativeFunction(
    Module.getExportByName('CoreFoundation', 'CFBundleCreate'),
    'pointer',
    [
        'pointer',            // allocator
        'pointer',            // url
    ]);
const TCCAccessResetForBundle = new NativeFunction(
    Module.getExportByName('/System/Library/PrivateFrameworks/TCC.framework/TCC', 'TCCAccessResetForBundle'),
    'int',
    [
        'pointer',            // service
        'pointer',            // url
    ]);
const TCCAccessReset = new NativeFunction(
    Module.getExportByName('/System/Library/PrivateFrameworks/TCC.framework/TCC', 'TCCAccessReset'),
    'void',
    [
        'pointer',            // service
    ]);
const TCCAccessCopyInformationForBundle = new NativeFunction(
    Module.getExportByName('/System/Library/PrivateFrameworks/TCC.framework/TCC', 'TCCAccessCopyInformationForBundle'),
    'pointer',
    [
        'pointer',            // url
    ]);
const CFRelease = new NativeFunction(
    Module.getExportByName('CoreFoundation', 'CFRelease'),
    'void',
    [
        'pointer',            // cf
    ]);

const kTCCServiceAll = NSString.stringWithString_("kTCCServiceAll");

if (getMyEntitlements()!["com.apple.private.tcc.manager"] === undefined) {
    // On iOS 16.5+ (maybe 16.4?) Apple changed SpringBoard (/System/Library/CoreServices/SpringBoard.app/SpringBoard)
    // entitlements and removed
    // ```xml
    // <key>com.apple.private.tcc.manager</key>
    // <true/>
    // ```
    // Adding
    // ```xml
    // <key>com.apple.private.tcc.manager.access.read</key>
    // <array>
    //     <string>kTCCServiceFocusStatus</string>
    // </array>
    console.log("This Mach-O doesn't support `TCCAccessReset(kTCCServiceAll);` because `com.apple.private.tcc.manager` entitlement missing!" );
}

rpc.exports = {
    // https://github.com/FouadRaheb/AppData/blob/eebc09cfb17375f04f5df08796754738d60b5e13/AppData/Classes/Model/ADAppData.m#L292-L300
    resetAppTccPermissionsByBundleId(bundleIdentifier: string): void {
        const appProxy = LSApplicationProxy.applicationProxyForIdentifier_(bundleIdentifier);
        const bundleURL = appProxy.$ivars["_bundleURL"];
        const bundle: NativePointer = CFBundleCreate(kCFAllocatorDefault, bundleURL);
        if (!bundle.isNull()) {
            TCCAccessResetForBundle(kTCCServiceAll, bundle);
            CFRelease(bundle);
        }
    },
    resetAppLocationPermissionsByBundleId(bundleIdentifier: string): void {
        const processInformationAgent = NSProcessInfo.processInfo();        // this is a shared object between processes
        const majorVersion: number = parseInt(processInformationAgent.operatingSystemVersion()[0]);
        if (majorVersion >= 16) {
            // On iOS 16+ Apple added this method that allows you to remove the entry from /private/var/root/Library/Caches/locationd/clients.plist.
            // While in the previous iOS versions, you could only change the authorization status to 0x0 with
            // setAuthorizationStatusByType_forBundleIdentifier_.
            CLLocationManager.resetLocationAuthorizationForBundleId_orBundlePath_(bundleIdentifier, NULL);
        } else CLLocationManager.setAuthorizationStatusByType_forBundleIdentifier_(0, bundleIdentifier)
    },
    resetNotificationPermissionsByBundleId(bundleIdentifier: string): void {
        // TODO: add support for iOS 12
        ObjC.chooseSync(BBDataProviderConnection)[0].removeDataProviderWithSectionID_(bundleIdentifier);
    },
    resetAllAppLocationPermission(): void {
        CLLocationManager.sharedManager().resetApps();
    },
    resetAllAppTccPermissions(): void {
        TCCAccessReset(kTCCServiceAll);
    },
    resetAllAppNotificationPermissions(): void {
        // TODO: add support for iOS 12
        const dict = ObjC.chooseSync(BBServer)[0].$ivars['_sectionInfoByID'];
        const bbDataProviderConnection = ObjC.chooseSync(BBDataProviderConnection)[0];
        const bundleIdentifiers = dict.allKeys();
        const count = bundleIdentifiers.count().valueOf();
        for (let i = 0; i !== count; i++)
            bbDataProviderConnection.removeDataProviderWithSectionID_(bundleIdentifiers.objectAtIndex_(i).toString());
    },
    resetAllAppNePermissions(): void {
        // How did I find the class NEConfigurationManager?
        // Well, using Ghidra on `/usr/libexec/nehelper` I discovered that it imports stuff from `NetworkExtension.framework`.
        // So, using `frida-trace` I searched all classes that start with NE*.
        const manager = NEConfigurationManager.sharedManager();
        const pendingBlocks: Set<ObjC.Block> = new Set();

        const completionHandler = new ObjC.Block({
            retType: 'void',
            argTypes: ['object', 'pointer'],
            implementation: function (configurations, error): void {
                pendingBlocks.delete(completionHandler);
                if (!error.isNull()) {
                    const err = new ObjC.Object(error);
                    throw new Error(err.toString());
                }
                const handler: ObjC.Block = new ObjC.Block({
                    argTypes: ["object"],
                    implementation: (): void => {
                        return;
                    },
                    retType: "void",
                });
                const count = configurations.count().valueOf();
                for (let index = 0; index !== count; index++)
                    manager.removeConfiguration_withCompletionQueue_handler_(
                        configurations.objectAtIndex_(index), ObjC.mainQueue, handler
                    );
                manager.repopulateNetworkPrivacyConfigurationResetAll_(true);
            }
        });
        pendingBlocks.add(completionHandler);

        // TODO: iOS 14+ support this permission. So should we add a `if`?
        manager.repopulateNetworkPrivacyConfigurationResetAll_(true);
        manager.loadConfigurationsWithCompletionQueue_handler_(ObjC.mainQueue, completionHandler);
    },
    // https://github.com/FouadRaheb/AppData/blob/eebc09cfb17375f04f5df08796754738d60b5e13/AppData/Classes/Model/ADAppData.m#L272-L279
    getTccPermissions(bundleIdentifier: string): string | null {
        const appProxy = LSApplicationProxy.applicationProxyForIdentifier_(bundleIdentifier);
        const bundleURL = appProxy.$ivars["_bundleURL"];
        const bundle: NativePointer = CFBundleCreate(kCFAllocatorDefault, bundleURL);
        if (!bundle.isNull()) {
            const array: ObjC.Object = new ObjC.Object(TCCAccessCopyInformationForBundle(bundle));
            CFRelease(bundle);
            return JSON.stringify(arrayFromNSArray(array));
        }
        return null;
    },
    getLocationAuthStatusByBundleId(bundleIdentifier: string): number {
        return CLLocationManager.authorizationStatusForBundleIdentifier_(bundleIdentifier);
    },
    // https://stackoverflow.com/a/46739087
    removeContactByInternalIdentifier(_internalIdentifier: string): boolean {
        const identifier = NSString.stringWithString_(_internalIdentifier);
        const identifiers = NSArray.arrayWithObjects_(identifier);
        const predicate = CNContact.predicateForContactsWithIdentifiers_(identifiers);
        const keysToFetch = NSArray.alloc().init();                                         // an empty NSArray
        const contacts = CNContactStore.alloc().init().unifiedContactsMatchingPredicate_keysToFetch_error_(predicate, keysToFetch, NULL);
        const count = contacts.count().valueOf();
        if (count >= 1) {
            const contact = contacts.objectAtIndex_(0).mutableCopy();
            const deleteRequest = CNSaveRequest.alloc().init();
            deleteRequest["- deleteContact:"](contact);
            return CNContactStore.alloc().init()["- executeSaveRequest:error:"](deleteRequest, NULL);
        }
        return false;
    },
    reboot(): void {
        FBSSystemService.sharedService().reboot();
    },
    shutdown(): void {
        FBSSystemService.sharedService().shutdown();
    },
    // TODO: Are [netctl](https://github.com/ProcursusTeam/netctl) features required in AnForA?
    getBrightness(): number {
        // based on https://github.com/doronz88/rpc-project/blob/59b0f41523/src/rpcclient/rpcclient/ios/backlight.py#L18
        return BrightnessSystemClient.alloc().init().copyPropertyForKey_('DisplayBrightness').valueForKey_('Brightness').floatValue();
    },
    setBrightness(value: number): void {
        BrightnessSystemClient.alloc().init().setProperty_forKey_(value, 'DisplayBrightness');
    },
    // these procedures are the result of RE of /System/Library/PrivateFrameworks/EmbeddedDataReset.framework/XPCServices/DeviceDataResetXPCServiceWorker.xpc/DeviceDataResetXPCServiceWorker
    terminateAllRunningApplications(): void {
        // class: DDRTaskTerminateAllRunningApplications
        const description = NSString.stringWithString_('com.apple.devicedatareset.terminateAllRunningApplications');
        FBSSystemService.sharedService()["- terminateApplicationGroup:forReason:andReport:withDescription:"](1, 5, false, description);
    },
    toggleAirplaneMode(): void {
        // class: DDRTaskDisableAirplaneMode
        const current: boolean = RadiosPreferences.alloc().init().airplaneMode();
        RadiosPreferences.alloc().init()["- setAirplaneMode:"](!current);
    },
    getAirplaneMode(): boolean {
        return RadiosPreferences.alloc().init().airplaneMode();
    },
    signOutOfAppStore(): void {
        // TODO: add support for iOS 12 & 13
        // class: DDRTaskSignoutAppleAccount
        AMSSignOutTask.alloc()["- performTask"]();
    },
}