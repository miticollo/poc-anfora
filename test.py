import os
import sys
import unittest

from appium import webdriver

# For more capabilities: https://appium.github.io/appium-xcuitest-driver/latest/capabilities/
capabilities = dict(
    platformName='ios',
    automationName='xcuitest',
    # https://guides.codepath.com/ios/Provisioning-Profiles
    # xcodebuild --help
    updatedWDABundleId='it.uniupo.dsdf.WebDriverAgentRunner',
    allowProvisioningDeviceRegistration=True,
    showXcodeLog=True,
    browserName='safari',
)

appium_server_url = 'http://localhost:4723'


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
    if len(sys.argv) != 3:
        # https://stackoverflow.com/a/4152986
        print("Usage: " + os.path.basename(__file__) + " <TEAM_ID> <UDID>")
        sys.exit(1)

    capabilities['xcodeOrgId'] = sys.argv[1]
    capabilities['udid'] = sys.argv[2]

    suite = unittest.TestLoader().loadTestsFromTestCase(TestAppium)
    unittest.TextTestRunner(verbosity=2).run(suite)
