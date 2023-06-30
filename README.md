# PoC AnForA

<iframe width="560" height="315" src="https://www.youtube.com/embed/XQtXN6h2v_o" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

Features:

## How to run

1. Clone this project
   ```shell
   git clone --depth=1 -j8 https://github.com/miticollo/poc-anfora.git
   cd poc-anfora
   ```
2. Download NodeJS dependencies
   <span><!-- https://appium.github.io/appium/docs/en/latest/quickstart/install/ --></span>
   ```shell
   npm -ddd install
   ```
3. Install `pip` dependencies
   ```shell
   brew -v install cairo gobject-introspection
   ```
4. Download Python dependencies
   <span><!-- https://stackoverflow.com/a/15593865 --></span>
   <span><!-- https://appium.github.io/appium/docs/en/latest/quickstart/test-py/ --></span>
   ```shell
   pip -vvv install --upgrade -r requirements.txt
   ```
5. Choose Xcode version **if you want to build WDA app, otherwise skip this step**
   <span><!-- https://appium.github.io/appium-xcuitest-driver/latest/multiple-xcode-versions/ --></span>
   ```shell
   export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer # adjust path if necessary
   ```
6. Run Appium server
   <span><!-- https://stackoverflow.com/a/45164863 --></span>
   ```shell
   npx appium server --session-override
   ```
7. <span id="team-id"></span>
   Open a new terminal window and choose appropriate options to properly run the PoC.
   - If you have already installed the WDA app you can run the Python script without any particular options on **all supported OSs**:
     ```shell
     python ./src/main.py UDID -o DUMP_PATH
     ```
     To find `<UDID>`, you can use [`idevice_id -l`](https://github.com/libimobiledevice/libimobiledevice/blob/master/tools/idevice_id.c).
   - If you have **not** already installed the WDA app and
     - your OS is macOS
       ```shell
       python ./src/main.py UDID -o DUMP_PATH -b it.uniupo.dsdf.WebDriverAgentRunner --team-id <TEAM_ID>
       ```
        The procedure to retrieve your `<TEAM_ID>` depends on whether you are enrolled in the Apple Developer program or not.
        If you are enrolled in the program, you can follow [this guide](https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/) to find your `<TEAM_ID>`.
        However, if you have a free account, you must create a blank project with Xcode and then run `utility/devteamid.sh` with the Apple ID that you used to create the previous project.
        When you create a new project, Xcode downloads a provisioning file and generates an identity (certificate + private key).
        <span><!-- https://www.ibm.com/docs/en/ibm-mq/9.3?topic=certificates-distinguished-names --></span>
        The `Organizational Unit (OU)` attribute in this X.509 certificate is set to `<TEAM_ID>` and it is assigned to you by Apple.
        Remember that `<TEAM_ID>` is unique and immutable, so **save it for future uses**.
        You can also find this certificate by exploring the Keychain app, in particular looking in `login.keychain`.
     - your OS is **not** macOS
       1. Follow [below instructions](#other-oss) to prepare a Docker container with macOS.
       2. Open Xcode
          ```shell
          open -a /Applications/Xcode.app # adjust path if necessary
          ```
       3. Add your Apple ID to Xcode.
          Go to `Settings` > `Accounts`.
       4. Create a blank project using the Apple ID you have just added to Xcode.
          **This step is FUNDAMENTALLY because without it, you can't use `utility/devteamid.sh` because there is no identity in Keychain.**
       5. Close Xcode.
       6. [Pass through iPhone to container](https://github.com/sickcodes/Docker-OSX#usbfluxd-iphone-usb---network-style-passthrough-osx-kvm-docker-osx)
       7. Unlock the `login.keychain`.
          Add the following command before Appium server start command.
          <span><!-- https://stackoverflow.com/a/20208104 --></span>
          ```shell
          security unlock-keychain -p PASSWORD login.keychain && npx appium server --session-override
          ```
          > **Warning**<br/>
          > This is not SAFE!
          > But it permits the building **over SSH** without GUI.
       8. Finally run
          ```shell
           python ./src/main.py UDID -b it.uniupo.dsdf.WebDriverAgentRunner --team-id <TEAM_ID> --install-wda-only
           ```
          to (re)install the WDA app.
          Find your `TEAM_ID` using `utility/devteamid.sh` with the Apple ID that you used for Xcode.
       9. Shutdown the container.
          Now you can use Linux or Windows!

     > **Note**<br/>
     > If `appium` server fails with error: `Failed to register bundle identifier: The app identifier "it.uniupo.dsdf.WebDriverAgentRunner.xctrunner" cannot be registered to your development team because it is not available. Change your bundle identifier to a unique string to try again.`
     > You can fix it with the option `[-b BUNDLE_ID]`.

## Other OSs

To support other operating systems, we will use Docker, specifically [this project](https://github.com/sickcodes/Docker-OSX).
Please note that I have only tested this project on Linux. 
However, the project also provides [instructions for Windows](https://github.com/sickcodes/Docker-OSX#id-like-to-run-docker-osx-on-windows).

### Linux

I'll show what you must do on your host and on macOS separately.

#### On your host

> **Note**<br/>
> I used Manjaro as Linux Distro.

The information for the project that I linked before is extensive, so here are the main steps with some additions:

1. Setup **Linux** to [pass through iPhone to container](https://github.com/sickcodes/Docker-OSX#usbfluxd-iphone-usb---network-style-passthrough-osx-kvm-docker-osx).
   If you want to use an SSH session, you can install `sshpass` on your Linux machine using a package manager such as `yum`, `apt-get`, or `pacman`, depending on your distribution.
   For example, in my case, I used the following command:
   ```shell
   yay -S sshpass
   ```
   Then, run the following command to establish an SSH connection:
   ```shell
   # adjust the values to match your environment
   sshpass -p <password> ssh -v user@localhost -p 50922
   ```
   > **Warning**<br/>
   > <span><!-- https://github.com/sickcodes/Docker-OSX/issues/549#issuecomment-1298595576 --></span>
   > You need to enable remote login in the virtual macOS first.
2. [Initial setup](https://github.com/sickcodes/Docker-OSX#initial-setup)
3. Choose a macOS release. I chose [Ventura](https://github.com/sickcodes/Docker-OSX#ventura-).
   To increase verbosity, you can pass the **global option** `-l` with the argument `debug` to `docker`.
   Pass the option `--name 'anfora_appium'` to correctly identify our container.
4. In another terminal window start a TCP listener on port 3000 using `socat`, a more versatile and powerful networking tool than `nc`
   <span><!-- https://discord.com/channels/871502559842541679/871502643678281729/971015723805708359 --></span>
   ```shell
   socat TCP-LISTEN:3000,reuseaddr,fork -
   ```
   In this way any incoming connections will be forked into a new process (`fork` option), so that multiple clients can connect simultaneously. 
   The `-` at the end specifies that data from the connection should be written to the standard output.
   We will use it as shared clipboard between host and guest if necessary.
5. If you have shut down the container, you can restart it by running:
   ```shell
   docker -l debug start -ai "$(docker ps -a -f 'name=anfora_appium' -q)"
   ```
   > **Note**<br/>
   > This command lists all containers (running and stopped) and filters the output based on the container name.
   > It then prints only the short UUID identifier using the `-q` option, which is used as input for the `docker start` command.

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
   <span><!-- https://discord.com/channels/871502559842541679/871502643678281729/971015886196604948 --></span>
10. In another terminal window and run `git` to install Command Line Tools for Xcode.
    **This doesn't install Xcode.**
11. [Install HomeBrew](https://brew.sh/#install).
12. To install Xcode, we will use a CLI tool called [`xcodes`](https://github.com/RobotsAndPencils/xcodes) for two reasons:
    - this app automatically manages two or more different versions of Xcode and
    - another advantage is that `xcodes` can use [`aria2`](https://aria2.github.io/), a CLI tool to speed up the download of Xcode.

    Every version of Xcode comes with its own SDK version, which means that you need to install an old version of Xcode to use an old SDK version.
    For example, if you want to install the latest version of Xcode from the App Store and also need version 11.7 to compile your app for iOS 12+ and arm64e, you can download Xcode 11.7 from [here](https://developer.apple.com/services-account/download?path=/Developer_Tools/Xcode_11.7/Xcode_11.7.xip).
    The file you download is a [`.XIP` archive](https://github.com/saagarjha/unxip#design) that you can extract using Archive Utility. 
    Before moving it to `/Applications`, make sure to rename the `.app` folder to avoid conflicts with `Xcode.app`, which is the latest version. 
    `xcodes` does all of this for you automatically.
    Furthermore, `aria2` uses up to 16 connections to download files, making it 3-5x faster than [URLSession](https://developer.apple.com/documentation/foundation/urlsession).
    ```shell
    brew -v install robotsandpencils/made/xcodes aria2
    # Adjust XCODES_USERNAME and XCODES_PASSWORD to use your Apple ID
    XCODES_USERNAME="20024182@studenti.uniupo.it" XCODES_PASSWORD="..." xcodes install --latest --experimental-unxip --empty-trash
    ```
    This step takes a long time, so in the meantime, you can continue with the next step.

    > **Note**<br/>
    > It is not possible to pass `XCODES_USERNAME` and `XCODES_PASSWORD` to the container with `docker run` options `-e` and `--env-file`, because Docker-OSX creates a Docker container based on ArchLinux, then installs in it QEMU.
    > This is necessary because Docker-OSX uses another project called [OSX-KVM](https://github.com/kholia/OSX-KVM) under the hood.<br/>
    > To prove that an ArchLinux Docker container is used under macOS, we can use the following Bash command inside the container:
    > ```shell
    > docker exec -it 'anfora_appium' bash -c 'grep -e vmx -e svm /proc/cpuinfo'
    > ```
    > This command checks if a [requirement](https://github.com/kholia/OSX-KVM#requirements) is met.

13. To install Python we will use [`pyenv`](https://github.com/pyenv/pyenv) a version manager with two important feature:
    - it automatically retrieves, compiles and installs a specific Python version and
    - you can choose a specific version per project.

      1. [Install `pyenv`](https://github.com/pyenv/pyenv#homebrew-in-macos) and [set up the build environment](https://github.com/pyenv/pyenv/wiki#suggested-build-environment)
         ```shell
         brew -v update
         brew -v install pyenv openssl readline sqlite3 xz zlib tcl-tk
         ```
      2. Show hidden files
         ```shell
         defaults write com.apple.Finder AppleShowAllFiles true
         killall Finder
         ```
      3. [Add autocompletion and shims](https://github.com/pyenv/pyenv#advanced-configuration) to your shell environment
         ```shell
         pyenv init
         ```
         and follow instructions.
      3. Install the current latest Python 3 version, in my case 3.11.4
         ```shell
         pyenv install -v 3.11.4
         pyenv global 3.11.4
         ```
         To list all supported Python version you can run: `pyenv install -l`.
         This list can be updated every time that a `pyenv` update is available.

14. We have almost done!
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
      4. To set [the latest version of NodeJS as the default one](https://github.com/nvm-sh/nvm#set-default-node-version):
         ```shell
         nvm alias default node
         ```
15. [Install `usbfluxd` to replace `usbmuxd` socket file](https://github.com/sickcodes/Docker-OSX#connect-to-a-host-running-usbfluxd) to connect iPhone from host to container over network.
16. Enable [parallel building](https://theos.dev/docs/parallel-building)
    ```shell
    echo '' >> ~/.zprofile
    echo PATH=\"$(brew --prefix make)/libexec/gnubin:\$PATH\" >> ~/.zprofile
    ```
    then restart shell.
17. Done! Go to [previously section](#how-to-run).

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

#### How to Integrate Docker Container into AnForA Workflow?



> **Warning**<br/>
> `xcodebuild` requires that the developer account used is in Xcode. 
> Therefore, you must add it by going to `Preferences...` > `Accounts`.
