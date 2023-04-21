#!/usr/bin/env python3

import argparse
import atexit
import logging
import multiprocessing
import re
import sys
import threading
import time
from multiprocessing import Process, Event
from sys import platform
from typing import TYPE_CHECKING, Any, Dict

import frida
import ioscreen.util
import tidevice
import usb
from appium import webdriver
from appium.options.common import AppiumOptions
from appium.webdriver.common.appiumby import AppiumBy
from ioscreen.util import find_ios_device, record_gstreamer
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

if TYPE_CHECKING:
    from appium.webdriver.webdriver import WebDriver
    from appium.webdriver.webelement import WebElement

desired_caps: Dict[str, Any] = {
    'platformName': 'iOS',
    'automationName': 'XCUITest',
    'wdaLaunchTimeout': 3 * 1000 * 60,
}

SERVER_URL_BASE = 'http://127.0.0.1:4723'
BUNDLE_ID = 'com.loki-project.loki-messenger'
WDA_CF_BUNDLE_NAME = 'WebDriverAgentRunner-Runner'


def wait_for_element(driver: 'WebDriver', locator: str, value: str, timeout_sec: float = 10) -> 'WebElement':
    return WebDriverWait(driver, timeout_sec).until(EC.presence_of_element_located((locator, value)))


def test_appium(device):
    driver: WebDriver = webdriver.Remote(SERVER_URL_BASE, options=AppiumOptions().load_capabilities(desired_caps))
    driver.update_settings({'snapshotMaxDepth': 100})

    spawned_pid = device.spawn([BUNDLE_ID])
    device.attach(spawned_pid, realm="native")
    device.resume(spawned_pid)
    try:
        wait_for_element(driver, AppiumBy.XPATH, '(//XCUIElementTypeCell[@name="Conversation list item"])[1]').click()
        el = driver.find_element(by=AppiumBy.XPATH, value='//XCUIElementTypeTextView[@name="Message input box"]')
        el.click()
        el.send_keys("Hello by Appium!")
        driver.find_element(by=AppiumBy.ACCESSIBILITY_ID, value='Send message button').click()
        if driver.is_keyboard_shown():
            print('keyboard is visible!')
    except Exception as e:
        print('***********************************************')
        print(e)
        print('***********************************************')
        print('===============================================')
        print(driver.page_source)
        print('===============================================')
    device.kill(spawned_pid)

    if driver:
        driver.quit()


def check_team_id(value):
    up = str.upper(value)
    if not re.match(r'^[A-Z0-9]{10}$', up):
        raise argparse.ArgumentTypeError('Team ID must be a 10-character string of uppercase letters and numbers.')
    return up


def ephemeral_port(value):
    if value is None:
        return value
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a valid integer value.")

    if not (1024 <= port <= 65535):
        raise argparse.ArgumentTypeError(f"{port} is not a valid ephemeral port.")

    return port


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


def parsing():
    parser = argparse.ArgumentParser(description='MWE for Appium+frida testing on iOS devices.')
    parser.add_argument('UDID', help='the UDID of the iOS device to test', type=nonempty_string)
    parser.add_argument('IOS_VERSION', help='the version of iOS running on the device', type=nonempty_string)
    parser.add_argument('-b', '--bundle-id', metavar='BUNDLE_ID', help='set the bundle identifier of the installed app',
                        type=nonempty_string)
    parser.add_argument('-t', '--timeout', metavar='MINUTES', type=check_positive,
                        help='set the timeout for WebDriverAgent to become pingable (in minutes)')
    parser.add_argument('--team-id', metavar='TEAM_ID', type=check_team_id,
                        help='set the 10-character team identifier for your Apple developer account')
    parser.add_argument('-p', '--port', metavar='PORT', type=ephemeral_port, default=8100,
                        help='it will be used to forward traffic from this host to real iOS devices over USB')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--mjpeg', metavar='PORT', type=ephemeral_port, default=None, nargs='?', const=9100,
                       help='show a mirror of the screen of your iPhone using WDA MJPEG Server')
    group.add_argument('--quicktime', action='store_true', default=False,
                       help='show a mirror of the screen of your iPhone using QuickTime protocol')
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    args = parser.parse_args()

    if args.team_id is None and args.bundle_id is not None:
        parser.error('The --bundle-id option requires --team-id.')
    return args


def wait_until(predicate, timeout=10, period=0.25, *args, **kwargs):
    must_end = time.time() + timeout
    while time.time() <= must_end:
        if predicate(*args, **kwargs):
            return True
        time.sleep(period)
    return False


def mirroring_mjpeg(port):
    pass


def mirroring_quicktime(udid: str, level: int, event: Event):
    ioscreen.util.set_logging_level(level)
    device: usb.Device = find_ios_device(udid)
    record_gstreamer(device, event)


# define a function to terminate process
def clean_up():
    if process is not None and process.is_alive():
        process.terminate()


def main():
    args = parsing()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        desired_caps.update({'showIOSLog': True})

    desired_caps.update({
        'udid': args.UDID,
        'platformVersion': args.IOS_VERSION,
        'wdaLocalPort': args.port
    })

    if args.timeout is not None:
        desired_caps['wdaLaunchTimeout'] = args.timeout * 1000 * 60
    if args.bundle_id is not None:
        desired_caps.update({'updatedWDABundleId': args.bundle_id})

    global process
    process = None
    if args.quicktime:
        # create a shared event object
        event: multiprocessing.Event = Event()
        # create a process
        if args.verbose:
            process = Process(target=mirroring_quicktime,
                              args=(desired_caps['udid'].replace('-', ''), logging.DEBUG, event,))
        else:
            process = Process(target=mirroring_quicktime,
                              args=(desired_caps['udid'].replace('-', ''), logging.INFO, event,))
        # run the new process
        process.start()
        atexit.register(clean_up)
        # wait for the event to be set
        event.wait()

    t = tidevice.Device(udid=desired_caps['udid'])
    device = frida.get_device(desired_caps['udid'])

    if args.team_id is not None:
        if platform != "darwin":
            sys.exit(f'You can\'t compile WDA on {platform}!')
        desired_caps.update({
            'xcodeOrgId': args.team_id,
            'allowProvisioningDeviceRegistration': True,
            'showXcodeLog': True
        })
    else:
        try:
            device.get_process(WDA_CF_BUNDLE_NAME)
        except frida.ProcessNotFoundError:
            try:
                desired_caps.update({
                    'useSimpleBuildTest': False,
                    'usePrebuiltWDA': True
                })
                bundle_id = [app for app in device.enumerate_applications() if app.name == WDA_CF_BUNDLE_NAME][0].identifier
                if args.verbose:
                    t.debug = True
                threading.Thread(target=t.xcuitest, args=(bundle_id,), kwargs={}, daemon=True).start()
                wait_until(lambda: len([proc for proc in frida.get_usb_device().enumerate_processes() if
                                        proc.name == WDA_CF_BUNDLE_NAME]) > 0)
            except IndexError:
                sys.exit(f'{WDA_CF_BUNDLE_NAME} is not installed!')

    test_appium(device)


if __name__ == '__main__':
    main()
