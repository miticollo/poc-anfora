import {hookContact} from "./lib/contact.js";
import {hookKeychain} from "./lib/keychain.js";

hookContact();
hookKeychain();
// TODO: SSL unpinning
// TODO: DB password sniffing
// TODO: JB bypass.
//  It is not possible to do it using Frida because too many hooks are required.
//  The best solution is to use a tweak but ALL tweaks changes the behaviour of the app.
//  Indeed, some functions/syscalls SOMETIMES (not ALWAYS) could be required a patch.
// TODO: Frida bypass
