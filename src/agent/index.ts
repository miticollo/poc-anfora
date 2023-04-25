const LSApplicationProxy = ObjC.classes.LSApplicationProxy
const NSBundle = ObjC.classes.NSBundle
const bundleIdentifier = NSBundle.mainBundle().bundleIdentifier().toString()
const appProxy = LSApplicationProxy.applicationProxyForIdentifier_(bundleIdentifier)
const keys = appProxy.groupContainerURLs().allKeys()
const count = keys.count().valueOf();
const appGroups = [];
for (let i = 0; i !== count; i++) {
    let url = appProxy.groupContainerURLs().objectForKey_(keys.objectAtIndex_(i))
    appGroups.push({
        'groupIdentifier': keys.objectAtIndex_(i).toString(),
        'path': url.path().toString()
    })
}
send(appGroups)