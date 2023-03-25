# Appium on iOS stock

You must enable Remote Automation and Web Inspector in Safari Advanced settings.

> **Note**<br/>
> Disk Developer Image is not required.
> Because Appium automatically mount it.

To run WDA app it is necessary to trust your developer account in `Settings` > `General` > `Device Management` (
or `Profiles` on some iDevices).
So to do this you must be quick mainly after the app is installed when compilation is not still finished you can trust
your developer account.
If you don't do that on time script will fail.<br/>
If you prefer you can sideload the [blank-app](https://github.com/miticollo/blank-app/releases/latest) with the same
account that you will use for WDA app.
In this way you can trust developer without any time problems.

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
   python ./test.py <TEAM_ID> <UDID>
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

To support the other operating systems we will use Docker.
In particular, we can use [this project](https://github.com/sickcodes/Docker-OSX).
I tested it **only on Linux** but the project
provides [instructions also for Windows](https://github.com/sickcodes/Docker-OSX#id-like-to-run-docker-osx-on-windows).

This procedure can't do automatically because to install and configure Xcode properly is necessary to insert Apple ID,
its password and the 2FA code.
And to do this you must interact with UI, so to automate it you would have to use Appium.
Furthermore, to skip the initial setup you would have to use a pre-installed Docker image uploaded
on [Docker Hub](https://hub.docker.com).
The problem with this solution is that required a lot of bandwidth to upload and download image (
e.g. [Catalina](https://github.com/sickcodes/Docker-OSX#run-catalina-pre-installed-)).

### Linux

I'll show what you must do on your host and on macOS separately.

#### On your host

> **Note**<br/>
> I used Manjaro as Linux Distro.

The info for the project - that I linked before - are a lot.
So here I link the main steps with some my additions:

1. Setup **Linux**
   to [pass through iPhone to container](https://github.com/sickcodes/Docker-OSX#usbfluxd-iphone-usb---network-style-passthrough-osx-kvm-docker-osx).
2. [Initial setup](https://github.com/sickcodes/Docker-OSX#initial-setup)
3. Choose an macOS release: I chose [Monterey](https://github.com/sickcodes/Docker-OSX#monterey-)
   To increase verbosity you can pass the **global option** `-l` with argument `debug` to `docker`.
4. If you shut down the container you can restart it
   following [these instructions](https://github.com/sickcodes/Docker-OSX#start-the-same-container-later-persistent-disk).

#### On macOS side

Now some instruction to set up macOS.
These commands will be run inside container, so they are independently of host OS (Windows or Linux).

5. After boot, you are in recovery mode.
   If necessary change the language otherwise the OS will be installed with the current language: English(US).
   To do this: `File` > `Choose Language...`
6. [Erase disk](https://github.com/sickcodes/Docker-OSX#additional-boot-instructions-for-when-you-are-creating-your-container)
7. After installation - when desktop appears - you can run some commands to optimize macOS:
   1. [Disable heavy login screen wallpaper](https://github.com/sickcodes/osx-optimizer#disable-heavy-login-screen-wallpaper)
   2. [Reduce Motion & Transparency](https://github.com/sickcodes/osx-optimizer#reduce-motion--transparency)
   3. [Disable screen locking](https://github.com/sickcodes/osx-optimizer#disable-screen-locking)
   4. [Show a lighter username/password prompt instead of a list of all the users](https://github.com/sickcodes/osx-optimizer#show-a-lighter-usernamepassword-prompt-instead-of-a-list-of-all-the-users)

   If you want you can also choose others optimizations.
8. Open a terminal and run `git` to install Command Line Tools for Xcode.
   **This doesn't install Xcode.**
9. To install Xcode we will use [Xcodes](https://github.com/RobotsAndPencils/XcodesApp) for two reasons:
   - this app automatically manages two or more different versions of Xcode and
   - another advantage is that Xcodes is shipped with [`aria2`](https://aria2.github.io/) a CLI tool to speed up the
     download of Xcode.

   Every Xcode has its own SDK version, so to use an old SDK version you must install an old Xcode version.
   So for example if you want to install the latest Xcode version from App Store and the version 11.7 to compile your
   app for iOS 12+ and arm64e.
   You can download it
   from [here](https://developer.apple.com/services-account/download?path=/Developer_Tools/Xcode_11.7/Xcode_11.7.xip).
   It is [`.XIP` archive](https://github.com/saagarjha/unxip#design) that you can extract with Archive Utility.
   But - before move it on `/Applications` - it is necessary to rename `.app` folder to avoid conflicts
   with `Xcode.app` (the latest version).
   Xcodes does all this for you.
   Furthermore, `aria2` uses up to 16 connections to download 3-5x faster
   than [URLSession](https://developer.apple.com/documentation/foundation/urlsession).
10. To install Python we will use [`pyenv`](https://github.com/pyenv/pyenv) a version manager with two important
    feature:
   - it automatically retrieves, compiles and installs a specific Python version and
   - you can choose a specific version per project.

      1. [Install `pyenv`](https://github.com/pyenv/pyenv#homebrew-in-macos)
         and [set up the build environment](https://github.com/pyenv/pyenv/wiki#suggested-build-environment)
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

11. We have almost done!
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
12. [Install `usbfluxd` to replace `usbmuxd` socket file](https://github.com/sickcodes/Docker-OSX#connect-to-a-host-running-usbfluxd)
    to connect iPhone from host to container over network.
13. Done! Go to [previously section](#how-to-run).

## Appium Inspector

[Here](https://github.com/appium/appium-inspector/releases/tag/v2023.3.1) you can find the latest version.
