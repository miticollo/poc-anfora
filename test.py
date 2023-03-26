import os
import sys
import unittest

from appium import webdriver

# For more capabilities: https://appium.github.io/appium-xcuitest-driver/latest/capabilities/
capabilities = dict(
    platformName='ios',
    automationName='xcuitest',
    # xcodebuild --help
    updatedWDABundleId='it.uniupo.dsdf.WebDriverAgentRunner',
    allowProvisioningDeviceRegistration=True,
    showXcodeLog=True,
    browserName='safari',
    wdaLaunchTimeout=60 * 1000 * 3,  # 3 minutes
)

appium_server_url = 'http://localhost:4723'


def print_usage():
    script_name = os.path.basename(__file__)
    print(f"Usage: {script_name} <TEAM_ID> <UDID> [<TIMEOUT>] [<BUNDLE_ID>]", file=sys.stderr)


def validate_timeout_arg(arg):
    try:
        minutes = int(arg)
        if minutes <= 0:
            print("<TIMEOUT> must be a positive integer!", file=sys.stderr)
            return None
        return 60 * 1000 * minutes
    except ValueError:
        print("<TIMEOUT> must be an integer!", file=sys.stderr)
        return None


class TestAppium(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = webdriver.Remote(appium_server_url, capabilities)

    def tearDown(self) -> None:
        if self.driver:
            self.driver.quit()

    def test(self):
        # https://github.com/danielpaulus/ios-appium-on-linux/blob/8bd077fedadf1110d27d74a321b72b55bd5c413d/client/test.js#L22-L24
        self.driver.get("https://youtu.be/8v5f_ybSjHk")
        self.driver.implicitly_wait(5)  # waits 5 seconds
        self.driver.activate_app("com.apple.camera")


if __name__ == '__main__':
    if len(sys.argv) < 3 or len(sys.argv) > 5:
        print_usage()
        sys.exit(1)

    capabilities.update({
        'xcodeOrgId': sys.argv[1],
        'udid': sys.argv[2]
    })

    if len(sys.argv) == 4:
        timeout = validate_timeout_arg(sys.argv[3])
        if timeout:
            capabilities['wdaLaunchTimeout'] = timeout
    elif len(sys.argv) == 5:
        timeout = validate_timeout_arg(sys.argv[3])
        if timeout:
            capabilities['wdaLaunchTimeout'] = timeout
            capabilities['updatedWDABundleId'] = sys.argv[4]

    suite = unittest.TestLoader().loadTestsFromTestCase(TestAppium)
    unittest.TextTestRunner(verbosity=2).run(suite)
