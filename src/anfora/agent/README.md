# iOS daemons

An incomplete list of iOS 16.5 daemons.
For more details, see [this Reddit post](https://www.reddit.com/r/jailbreak/comments/10v7j59/tutorial_list_of_ios_daemons_and_what_they_do/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button) and [its answer](https://www.reddit.com/r/jailbreak/comments/10v7j59/comment/j8s1lgj/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button).

```shell
cd /System/Library/LaunchDaemons
for f in $(ls -1 -I 'com.apple.SpringBoard.plist' -I 'com.apple.applecamerad.plist' -I 'com.apple.backboardd.plist' \
  -I 'com.apple.bluetoothd.plist' -I 'com.apple.contactsd.plist' -I 'com.apple.email.maild.plist' \
  -I 'com.apple.locationd.plist' -I 'com.apple.nfcd.plist' -I 'com.apple.pasteboard.pasted.plist' \
  -I 'com.apple.photoanalysisd.plist' -I 'com.apple.searchd.plist' -I 'com.apple.sharingd.plist' \
  -I 'com.apple.shazamd.plist' -I 'com.apple.softwareupdateservicesd.plist' -I 'com.apple.tccd.plist' \
  -I 'com.apple.tipsd.plist' -I 'com.apple.itunesstored.plist' -I 'com.apple.runningboardd.plist' \
  -I 'com.apple.cfprefsd.xpc.daemon.plist' -I 'com.apple.cfprefsd.xpc.daemon.system.plist' \
  -I 'com.apple.lsd.plist' -I 'com.apple.trustd.plist' -I 'com.apple.containermanagerd.plist'\
  -I 'com.apple.nehelper-embedded.plist'); do 
  echo "${f}"
  launchctl unload "${f}">/dev/null 2>&1
done
```

## `/System/Library/LaunchDaemons/com.apple.applecamerad.plist`

Camera handler

## `/System/Library/LaunchDaemons/com.apple.backboardd.plist`

BackBoard is a daemon introduced in iOS 6 to take some workload off of SpringBoard. 
Its chief purpose is to handle events from the hardware, such as touches, button presses, and accelerometer information. 

## `/System/Library/LaunchDaemons/com.apple.bluetoothd.plist`

bluetooth module 

## `/System/Library/LaunchDaemons/com.apple.cfprefsd.xpc.daemon.plist`

Core Foundation preference sync (e.g. Setting language).
If you unload it, you must also unload `com.apple.cfprefsd.xpc.daemon.system.plist`, otherwise iDevice goes to panic.

## `/System/Library/LaunchDaemons/com.apple.contactsd.plist`

Contacts handler

## `/System/Library/LaunchDaemons/com.apple.containermanagerd.plist`

Mange App and Group containers

## `/System/Library/LaunchDaemons/com.apple.email.maild.plist`

You can disable it if you never use Apple Mail app.

## `/System/Library/LaunchDaemons/com.apple.itunesstored.plist`

Mandatory for iTunes Store  

## `/System/Library/LaunchDaemons/com.apple.locationd.plist`

Location services

## `/System/Library/LaunchDaemons/com.apple.lsd.plist`

Launch Services daemon 

## `/System/Library/LaunchDaemons/com.apple.nehelper-embedded.plist`

Manage ["If an app would like to connect to devices on your local network"](https://support.apple.com/library/content/dam/edam/applecare/images/en_US/iOS/ios-16-iphone-13-pro-keynote-recents-keynote-remote-local-network-prompt.png)

## `/System/Library/LaunchDaemons/com.apple.nfcd.plist`

NFC handler

## `/System/Library/LaunchDaemons/com.apple.pasteboard.pasted.plist`

copy paste

## `/System/Library/LaunchDaemons/com.apple.photoanalysisd.plist`

Photo Library

## `/System/Library/LaunchDaemons/com.apple.runningboardd.plist`

I don't know but without it any app opens.

## `/System/Library/LaunchDaemons/com.apple.searchd.plist`

Spotlight

## `/System/Library/LaunchDaemons/com.apple.sharingd.plist`

Generic "Share" action handler

## `/System/Library/LaunchDaemons/com.apple.shazamd.plist`

Shazam in Control Center

## `/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist`

Tells iOS how to start and execute an OTA update, feel free to remove. 
Although DO NOT attempt an OTA update with this removed. 
I feel that it also stops the update from happening if the device is jailbroken.  

## `/System/Library/LaunchDaemons/com.apple.tccd.plist`

Total and Complete Control -TCC’s background service is `tccd`, whose only documented control is in `tccutil`on macOS, which merely clears existing settings from lists in the Privacy tab of the Security & Privacy pane.
Its front end is that Privacy tab. 
In the unified log, TCC’s entries come from the subsystem com.apple.TCC.

## `/System/Library/LaunchDaemons/com.apple.tipsd.plist`

Tip of the day

## `/System/Library/LaunchDaemons/com.apple.trustd.plist`

PKI trust evaluation // Required for web surfing, required for safe certificates and to launch apps