# Appium on iOS stock

You must enable UI Automation in Safari settings.

> **Note**<br/>
> Disk Developer Image is not required.
> Because Appium automatically mount it.

## How to run
1. Clone this project
   ```shell
   git clone --depth=1 -j8 https://github.com/miticollo/test-appium.git
   cd test-appium
   ```
2. Download NodeJS dependencies
   <span><!-- https://appium.github.io/appium/docs/en/latest/quickstart/install/ --></span>
   ```shell
   npm install
   ```
3. Download Python dependencies
   <span><!-- https://stackoverflow.com/a/15593865 --></span>
   <span><!-- https://appium.github.io/appium/docs/en/latest/quickstart/test-py/ --></span>
   ```shell
   pip install -r requirements.txt
   ```
4. Choose Xcode version
   <span><!-- https://appium.github.io/appium-xcuitest-driver/latest/multiple-xcode-versions/ --></span>
   ```shell
   export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
   ```
5. Run Appium server with increased log level
   <span><!-- https://stackoverflow.com/a/45164863 --></span>
   ```shell
   npx appium server --log-level 'debug:info' --log-timestamp --local-timezone
   ```
6. In another terminal window, execute Python script
   <span><!-- https://appium.github.io/appium/docs/en/2.0/quickstart/test-py/ --></span>
   <span><!-- python ./test.py 'HS5TZXKJZJ' $(idevice_id -l) --></span>
   ```shell
   python ./test.py <TEAM_ID> <UDID>
   ```
   To find    

## Tested Devices and iOS Versions

- iPhone X: iOS 16.3.1
- iPad Pro (10,5"): iOS 16.3.1
- iPhone SE 2020: iOS 14.4.2
- iPhone XR: iOS 15.1b1
- iPad mini 2: iOS 12.5.6
- 