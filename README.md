# Appium on iOS stock

You must enable Remote Automation and Web Inspector in Safari Advanced settings.

> **Note**<br/>
> Disk Developer Image is not required.
> Because Appium automatically mount it.

To run the WDA app, it is necessary to trust your developer account by going to `Settings` > `General` > `Device Management` (or `Profiles` on some iDevices).
To ensure success, it is important to do this quickly, preferably after the app is installed, but before the compilation finishes.
If you do not complete this step in time, the script will fail. 
If you prefer, you can sideload the [blank-app](https://github.com/miticollo/blank-app/releases/latest) using the same account that you will use for the WDA app. 
This will allow you to trust the developer account without any time-related issues.

## How to run

If you don't have a macOS you can follow [below instructions](#other-oss).
When you have finished and your macOS container is ready you can follow these steps to install WDA app.

1. On iOS 16 real devices require enabling developer mode.
   After plug the iPhone
   run [`idevicedevmodectl`](https://github.com/libimobiledevice/libimobiledevice/blob/master/tools/idevicedevmodectl.c)
   ```shell
   idevicedevmodectl -d enable
   idevicedevmodectl -d confirm
   ```
2. Clone this project
   ```shell
   git clone --depth=1 -j8 https://github.com/miticollo/test-appium.git
   cd test-appium
   ```
3. Download NodeJS dependencies
   <span><!-- https://appium.github.io/appium/docs/en/latest/quickstart/install/ --></span>
   ```shell
   npm --ddd install
   ```
4. Download Python dependencies
   <span><!-- https://stackoverflow.com/a/15593865 --></span>
   <span><!-- https://appium.github.io/appium/docs/en/latest/quickstart/test-py/ --></span>
   ```shell
   pip -vvv install -r requirements.txt
   ```
5. Choose Xcode version
   <span><!-- https://appium.github.io/appium-xcuitest-driver/latest/multiple-xcode-versions/ --></span>
   ```shell
   export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
   ```
6. Run Appium server with increased log level
   <span><!-- https://stackoverflow.com/a/45164863 --></span>
   ```shell
   npx appium server --log-level 'debug:info' --log-timestamp --local-timezone
   ```
7. In another terminal window, execute Python script
   <span><!-- https://appium.github.io/appium/docs/en/2.0/quickstart/test-py/ --></span>
   <span><!-- python ./test.py 'HS5TZXKJZJ' $(idevice_id -l) --></span>
   ```shell
   python ./test.py <TEAM_ID> <UDID> [<TIMEOUT>]
   ```
   To find `<UDID>` you can
   use [`idevice_id -l`](https://github.com/libimobiledevice/libimobiledevice/blob/master/tools/idevice_id.c).
   To set `<TEAM_ID>` you can use `devteamid.sh`.

## Tested Devices and iOS Versions

- iPhone X: iOS 16.3.1
- iPad Pro (10,5"): iOS 16.3.1
- iPhone SE 2020: iOS 14.4.2
- iPhone XR: iOS 15.1b1
- iPad mini 2: iOS 12.5.6
- iPad mini 2: iOS 12.5.7
-

## Other OSs

To support other operating systems, we will use Docker, specifically [this project](https://github.com/sickcodes/Docker-OSX).
Please note that I have only tested this project on Linux. 
However, the project also provides [instructions for Windows](https://github.com/sickcodes/Docker-OSX#id-like-to-run-docker-osx-on-windows).

Unfortunately, this process cannot be automated, as it is necessary to manually enter your Apple ID, password, and 2FA code to properly install and configure Xcode.
To automate this process, you would need to use Appium. 
Additionally, to skip the initial setup, you would need to use a pre-installed Docker image from [Docker Hub](https://hub.docker.com).
Please note that this solution requires a significant amount of bandwidth to upload and download the required image (e.g., [Catalina](https://github.com/sickcodes/Docker-OSX#run-catalina-pre-installed-)).

### Linux

I'll show what you must do on your host and on macOS separately.

#### On your host

> **Note**<br/>
> I used Manjaro as Linux Distro.

The info for the project - that I linked before - are a lot.
So here I link the main steps with some my additions:

1. Setup **Linux** to [pass through iPhone to container](https://github.com/sickcodes/Docker-OSX#usbfluxd-iphone-usb---network-style-passthrough-osx-kvm-docker-osx).
2. [Initial setup](https://github.com/sickcodes/Docker-OSX#initial-setup)
3. Choose an macOS release: I chose [Monterey](https://github.com/sickcodes/Docker-OSX#monterey-)
   To increase verbosity you can pass the **global option** `-l` with argument `debug` to `docker`.
4. In another terminal window start a TCP listener on port 3000 using `socat`, a more versatile and powerful networking tool than `nc`
   ```shell
   socat TCP-LISTEN:3000,reuseaddr,fork -
   ```
   In this way any incoming connections will be forked into a new process (`fork` option), so that multiple clients can connect simultaneously. 
   The `-` at the end specifies that data from the connection should be written to the standard output.
5. If you shut down the container you can restart it
   following [these instructions](https://github.com/sickcodes/Docker-OSX#start-the-same-container-later-persistent-disk).

#### On macOS side

Now some instruction to set up macOS.
These commands will be run inside container, so they are independently of host OS (Windows or Linux).

6. After boot, you are in recovery mode.
   If necessary change the language otherwise the OS will be installed with the current language: English(US).
   To do this: `File` > `Choose Language...`
7. [Erase disk](https://github.com/sickcodes/Docker-OSX#additional-boot-instructions-for-when-you-are-creating-your-container)
8. After installation - when desktop appears - you can run some commands to optimize macOS:
   1. [Disable heavy login screen wallpaper](https://github.com/sickcodes/osx-optimizer#disable-heavy-login-screen-wallpaper)
   2. [Reduce Motion & Transparency](https://github.com/sickcodes/osx-optimizer#reduce-motion--transparency)
   3. [Disable screen locking](https://github.com/sickcodes/osx-optimizer#disable-screen-locking)
   4. [Show a lighter username/password prompt instead of a list of all the users](https://github.com/sickcodes/osx-optimizer#show-a-lighter-usernamepassword-prompt-instead-of-a-list-of-all-the-users)

   If you want you can also choose others optimizations.
9. To connect to the previously started listener, open a terminal and run the command `nc 172.17.0.1 3000`.
10. In another terminal window and run `git` to install Command Line Tools for Xcode.
    **This doesn't install Xcode.**
11. To install Xcode we will use [Xcodes](https://github.com/RobotsAndPencils/XcodesApp) for two reasons:
    - this app automatically manages two or more different versions of Xcode and
    - another advantage is that Xcodes comes with [`aria2`](https://aria2.github.io/) a CLI tool to speed up the download of Xcode.

    Every version of Xcode comes with its own SDK version, which means that you need to install an old version of Xcode to use an old SDK version.
    For example, if you want to install the latest version of Xcode from the App Store and also need version 11.7 to compile your app for iOS 12+ and arm64e, you can download Xcode 11.7 from [here](https://developer.apple.com/services-account/download?path=/Developer_Tools/Xcode_11.7/Xcode_11.7.xip).
    The file you download is a `.XIP` archive that you can extract using Archive Utility. 
    Before moving it to `/Applications`, make sure to rename the `.app` folder to avoid conflicts with `Xcode.app`, which is the latest version. 
    Xcodes does all of this for you automatically.
    Furthermore, `aria2` uses up to 16 connections to download files, making it 3-5x faster than [URLSession](https://developer.apple.com/documentation/foundation/urlsession).
12. To install Python we will use [`pyenv`](https://github.com/pyenv/pyenv) a version manager with two important feature:
    - it automatically retrieves, compiles and installs a specific Python version and
    - you can choose a specific version per project.

      1. [Install `pyenv`](https://github.com/pyenv/pyenv#homebrew-in-macos) and [set up the build environment](https://github.com/pyenv/pyenv/wiki#suggested-build-environment)
         ```shell
         brew -v update
         brew -v install pyenv openssl readline sqlite3 xz zlib tcl-tk
         ```
      2. [Add autocompletion and shims](https://github.com/pyenv/pyenv#advanced-configuration) to your shell environment
         ```shell
         eval "$(pyenv init -)"
         ```
      3. Restart shell.
      4. Install the current latest Python 3 version, in my case 3.11.2
         ```shell
         pyenv install 3.11
         pyenv global 3.11
         ```
         To list all supported Python version you can run: `pyenv install -l`.
         This list can be updated every time that a `pyenv` update is available.

13. We have almost done!
    We haven't yet install `npm` used by frida and Appium indeed `appium` server and its drivers are NodeJS programs.
    To install and manage it we will use a CLI tool called `nvm` which is a manager like `pyenv`.
      1. Install it with this [bash command](https://github.com/nvm-sh/nvm#install--update-script).
      2. [Verify installation](https://github.com/nvm-sh/nvm#verify-installation)
         ```shell
         command -v nvm
         ```
      3. Install the latest NodeJS and `npm` version:
         ```shell
          nvm install --latest-npm
         ```
14. [Install `usbfluxd` to replace `usbmuxd` socket file](https://github.com/sickcodes/Docker-OSX#connect-to-a-host-running-usbfluxd) to connect iPhone from host to container over network.
15. Done! Go to [previously section](#how-to-run).

#### Capability: `wdaLaunchTimeout`

I had to add this capability, which was [introduced in 2016](https://github.com/appium/appium-xcuitest-driver/pull/327#issue-196499064), otherwise `test.py` would have failed inside the container. 
This is because macOS has fewer resources, which causes `xcodebuild` to take longer to finish. 
During compilation, the `appium` server continuously pings WDA, but it only sends a response when it is installed and running on iOS. 
If the `wdaLaunchTimeout` (which has a default value of 60000 ms or 1 minute) expires before the app starts up on iOS, [the `appium` server tries to start a session anyway](https://github.com/appium/WebDriverAgent/blob/209d01a680003fd4864061487b1c3a4e0b76b2db/lib/xcodebuild.js#L399-L402), even if it's unsuccessful.
To avoid this, WebDriverAgent has a capability to change this timeout. 
I increased this value to 3 minutes, but if this is not sufficient, you can increase it using the third optional positional argument of `test.py`.

<span><!-- https://github.com/jlipps/asyncbox/blob/d0adc2145673c66c1b64c83739dfcaef4f59d3e1/lib/asyncbox.js#L79-L106 --></span>
In particular, when using the iOS driver, Appium [tries to connect once every 0.5 seconds (500 ms), until `wdaLaunchTimeout` is up](https://github.com/appium/WebDriverAgent/blob/209d01a680003fd4864061487b1c3a4e0b76b2db/lib/xcodebuild.js#L366).
More precisely, when `wdaLaunchTimeout` is 3 minutes (180000 ms), there will be [360 pings because 180000 / 500](https://github.com/appium/WebDriverAgent/blob/209d01a680003fd4864061487b1c3a4e0b76b2db/lib/xcodebuild.js#L370).
However, every [ping times out after 1 second (1000 ms)](https://github.com/appium/WebDriverAgent/blob/209d01a680003fd4864061487b1c3a4e0b76b2db/lib/xcodebuild.js#L377), so there will be at most 180 effective pings.

## Appium Inspector

[Here](https://github.com/appium/appium-inspector/releases/tag/v2023.3.1) you can find the latest version.
