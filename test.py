#!/usr/bin/env python3

import os
import sys
import time
import unittest
from typing import Any, Dict

import frida
from appium import webdriver
from appium.options.common import AppiumOptions
from appium.webdriver.common.appiumby import AppiumBy

# For more capabilities: https://appium.github.io/appium-xcuitest-driver/latest/capabilities/
# https://github.com/appium/python-client/blob/37e357b1371f0e76ddbe3d0954d3315df19c15d1/test/functional/ios/helper/desired_capabilities.py#L28-L36
desired_caps: Dict[str, Any] = {
    'platformName': 'iOS',
    'automationName': 'XCUITest',
    'updatedWDABundleId': 'it.uniupo.dsdf.WebDriverAgentRunner',
    # xcodebuild --help
    'allowProvisioningDeviceRegistration': True,
    'showXcodeLog': True,
    'wdaLaunchTimeout': 60 * 1000 * 3,  # 3 minutes
}

# https://github.com/appium/python-client/blob/37e357b1371f0e76ddbe3d0954d3315df19c15d1/test/helpers/constants.py#L1
SERVER_URL_BASE = 'http://127.0.0.1:4723'
# https://github.com/appium/python-client/blob/37e357b1371f0e76ddbe3d0954d3315df19c15d1/test/functional/ios/helper/desired_capabilities.py#L24
BUNDLE_ID = 'com.loki-project.loki-messenger'


def print_usage():
    script_name = os.path.basename(__file__)
    print(f"Usage: {script_name} <TEAM_ID> <UDID> <IOS_VERSION> [<TIMEOUT>] [<BUNDLE_ID>]", file=sys.stderr)


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
        self.session = self.device.attach(self.spawned_pid, realm="native").on
        self.device.resume(self.spawned_pid)
        self.driver.find_element(by=AppiumBy.ACCESSIBILITY_ID, value=[app for app in self.device.enumerate_applications() if app.identifier == BUNDLE_ID][0].name)
        self.driver.find_elements(by=AppiumBy.ACCESSIBILITY_ID, value='Conversation list item')[0].click()
        el = self.driver.find_element(by=AppiumBy.ACCESSIBILITY_ID, value='Message input box')
        el.click()
        el.send_keys("Hello by Appium!")
        self.driver.find_element(by=AppiumBy.ACCESSIBILITY_ID, value='Send message button').click()
        if self.driver.is_keyboard_shown():
            print('keyboard is visible!')
        self.device.kill(self.spawned_pid)


if __name__ == '__main__':
    if len(sys.argv) < 4 or len(sys.argv) > 6:
        print_usage()
        sys.exit(1)

    desired_caps['platformVersion'] = sys.argv[3]
    desired_caps.update({
        'xcodeOrgId': sys.argv[1],
        'udid': sys.argv[2]
    })

    if len(sys.argv) == 6:
        desired_caps['updatedWDABundleId'] = str(sys.argv[5])
        minutes = int(sys.argv[4])
        if minutes <= 0:
            print("<TIMEOUT> must be a positive integer!", file=sys.stderr)
            sys.exit(1)
        desired_caps['wdaLaunchTimeout'] = 60 * 1000 * minutes
    elif len(sys.argv) == 5:
        try:
            minutes = int(sys.argv[4])
            if minutes <= 0:
                print("<TIMEOUT> must be a positive integer!", file=sys.stderr)
                sys.exit(1)
            desired_caps['wdaLaunchTimeout'] = 60 * 1000 * minutes
        except ValueError:
            desired_caps['updatedWDABundleId'] = str(sys.argv[4])

    suite = unittest.TestLoader().loadTestsFromTestCase(TestAppium)
    unittest.TextTestRunner(verbosity=2).run(suite)
