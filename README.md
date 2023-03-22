# Appium on iOS stock

You must enable Remote Automation and Web Inspector in Safari Advanced settings.

> **Note**<br/>
> Disk Developer Image is not required.
> Because Appium automatically mount it.

To run WDA app it is necessary to trust your developer account in Settings > General > Device Management (or Profiles on some iDevices).
So to do this you must be quick mainly after the app is installed when compilation is not still finished you can trust your developer account.
If you don't do that on time script will fail.<br/>
If you prefer you can sideload the [blank-app](https://github.com/miticollo/blank-app/releases/latest) with the same account that you will use for WDA app.
In this way you can trust developer without any time problems.

## How to run
1. On iOS 16 real devices require enabling developer mode.
   After plug the iPhone run [`idevicedevmodectl`](https://github.com/libimobiledevice/libimobiledevice/blob/master/tools/idevicedevmodectl.c)
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
   To find `<UDID>` you can use [`idevice_id -l`](https://github.com/libimobiledevice/libimobiledevice/blob/master/tools/idevice_id.c).
   To set `<TEAM_ID>`, see [this](https://github.com/miticollo/blank-app#uuid).

## Tested Devices and iOS Versions

- iPhone X: iOS 16.3.1
- iPad Pro (10,5"): iOS 16.3.1
- iPhone SE 2020: iOS 14.4.2
- iPhone XR: iOS 15.1b1
- iPad mini 2: iOS 12.5.6
- iPad mini 2: iOS 12.5.7

## Windows/Linux

