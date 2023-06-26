import {hookContact} from "./lib/contact.js";
import {hookKeychain} from "./lib/keychain.js";

rpc.exports = {
    getIdentifier(path: string): string {
        const {
            NSBundle,
            NSURL,
        } = ObjC.classes;
        Thread.sleep(.05) // sleep for 50 ms
        let url = NSURL.fileURLWithPath_isDirectory_(path, true);
        let bundleIdUrl = NSBundle.bundleWithURL_(url);
        return bundleIdUrl.objectForInfoDictionaryKey_('CFBundleIdentifier').UTF8String();
    }
};

hookContact();
hookKeychain();
// TODO: network sniffing
// TODO: DB password sniffing