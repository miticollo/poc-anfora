#!/usr/bin/env python3

import argparse
import re
import unittest
from typing import TYPE_CHECKING, Any, Dict

import frida
from appium import webdriver
from appium.options.common import AppiumOptions
from appium.webdriver.common.appiumby import AppiumBy
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

if TYPE_CHECKING:
    from appium.webdriver.webdriver import WebDriver
    from appium.webdriver.webelement import WebElement

# For more capabilities: https://appium.github.io/appium-xcuitest-driver/latest/capabilities/
# https://github.com/appium/python-client/blob/37e357b1371f0e76ddbe3d0954d3315df19c15d1/test/functional/ios/helper/desired_capabilities.py#L28-L36
desired_caps: Dict[str, Any] = {
    'platformName': 'iOS',
    'automationName': 'XCUITest'
}

# https://github.com/appium/python-client/blob/37e357b1371f0e76ddbe3d0954d3315df19c15d1/test/helpers/constants.py#L1
SERVER_URL_BASE = 'http://127.0.0.1:4723'
# https://github.com/appium/python-client/blob/37e357b1371f0e76ddbe3d0954d3315df19c15d1/test/functional/ios/helper/desired_capabilities.py#L24
BUNDLE_ID = 'com.loki-project.loki-messenger'


# https://github.com/appium/python-client/blob/bb76339bc6b9bc3ae8eab7de1c416a1ff906317e/test/functional/test_helper.py#L81-L97
def wait_for_element(driver: 'WebDriver', locator: str, value: str, timeout_sec: float = 10) -> 'WebElement':
    return WebDriverWait(driver, timeout_sec).until(EC.presence_of_element_located((locator, value)))


class TestAppium(unittest.TestCase):
    def setUp(self) -> None:
        # https://github.com/appium/python-client/blob/37e357b1371f0e76ddbe3d0954d3315df19c15d1/test/functional/ios/safari_tests.py#L28
        self.driver = webdriver.Remote(SERVER_URL_BASE, options=AppiumOptions().load_capabilities(desired_caps))

    def tearDown(self) -> None:
        if self.driver:
            self.driver.quit()

    def test(self):
        self.device = frida.get_device(desired_caps['udid'])
        aux_kwargs = {}
        self.spawned_pid = self.device.spawn(BUNDLE_ID, stdio="inherit", **aux_kwargs)
        self.session = self.device.attach(self.spawned_pid, realm="native")
        self.device.resume(self.spawned_pid)
        wait_for_element(self.driver, AppiumBy.XPATH,
                         '(//XCUIElementTypeCell[@name="Conversation list item"])[1]').click()
        el = self.driver.find_element(by=AppiumBy.ACCESSIBILITY_ID, value='Message input box')
        el.click()
        el.send_keys("Hello by Appium!")
        self.driver.find_element(by=AppiumBy.ACCESSIBILITY_ID, value='Send message button').click()
        if self.driver.is_keyboard_shown():
            print('keyboard is visible!')
        self.device.kill(self.spawned_pid)


def check_team_id(value):
    up = str.upper(value)
    if not re.match(r'^[A-Z0-9]{10}$', up):
        raise argparse.ArgumentTypeError('Team ID must be a 10-character string of uppercase letters and numbers.')
    return up


def check_positive(value):
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise argparse.ArgumentTypeError(f'{value} is not a positive integer.')
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f'Can\'t cast `{value}` to a positive integer.')


def nonempty_string(value):
    if not value:
        raise argparse.ArgumentTypeError('Empty string found.')
    return value


def main():
    parser = argparse.ArgumentParser(description='MWE for Appium+frida testing on iOS devices.')
    parser.add_argument('UDID', help='the UDID of the iOS device to test', type=nonempty_string)
    parser.add_argument('IOS_VERSION', help='the version of iOS running on the device', type=nonempty_string)
    parser.add_argument('-b', '--bundle-id', metavar='BUNDLE_ID', help='set the bundle identifier of the installed app',
                        type=nonempty_string)
    parser.add_argument('-t', '--timeout', metavar='MINUTES', type=check_positive,
                        help='set the timeout for WebDriverAgent to become pingable (in minutes)')
    parser.add_argument('--team-id', metavar='TEAM_ID', type=check_team_id,
                        help='set the 10-character team identifier for your Apple developer account')
    args = parser.parse_args()

    if args.team_id is None and args.bundle_id is not None:
        parser.error('The --bundle-id option requires --team-id.')

    desired_caps.update({
        'udid': args.UDID,
        'platformVersion': args.IOS_VERSION
    })

    if args.timeout is not None:
        desired_caps.update({'wdaLaunchTimeout': args.timeout * 1000 * 60})
    if args.bundle_id is not None:
        desired_caps.update({'updatedWDABundleId': args.bundle_id})
    if args.team_id is not None:
        desired_caps.update({
            'xcodeSigningId': args.team_id,
            # xcodebuild --help
            'allowProvisioningDeviceRegistration': True,
            'showXcodeLog': True
        })
    else:
        desired_caps.update({'usePrebuiltWDA': True})

    suite = unittest.TestLoader().loadTestsFromTestCase(TestAppium)
    unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
    main()
