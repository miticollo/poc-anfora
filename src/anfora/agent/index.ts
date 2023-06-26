import {hookContact} from "./lib/contact.js";
import {hookKeychain} from "./lib/keychain.js";

hookContact();
hookKeychain();
// TODO: SSL unpinning
// TODO: DB password sniffing
