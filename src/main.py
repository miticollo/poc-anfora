#!/usr/bin/env python3

import atexit
import logging
import multiprocessing
import sys

import frida
import tidevice

from mirroring import clean_up
from my_appium import desired_caps
from utils import wait_until

SERVER_URL_BASE = 'http://127.0.0.1:4723'
BUNDLE_ID = 'com.loki-project.loki-messenger'
WDA_CF_BUNDLE_NAME = 'WebDriverAgentRunner-Runner'
EXPERIMENT_NAME = "SampleExperiment"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AnForA")


def parsing():
    """Return args parsed."""
    import argparse
    from utils import nonempty_string, check_positive, check_team_id, ephemeral_port
    parser = argparse.ArgumentParser(description='PoC for AnForA on iOS devices.')
    parser.add_argument('UDID', help='the UDID of the iOS device to test', type=nonempty_string)
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
    if args.port == args.mjpeg:
        parser.error('Port conflict.')
    return args


def main():
    args = parsing()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        desired_caps.update({'showIOSLog': True})

    desired_caps.update({
        'udid': args.UDID,
        'wdaLocalPort': args.port,
    })

    if args.timeout is not None:
        desired_caps['wdaLaunchTimeout'] = args.timeout * 1000 * 60
    if args.bundle_id is not None:
        desired_caps.update({'updatedWDABundleId': args.bundle_id})

    if args.quicktime:
        # create a shared event object
        event: multiprocessing.Event = multiprocessing.Event()
        # create a process
        from mirroring import mirroring_quicktime
        process = multiprocessing.Process(target=mirroring_quicktime,
                                          args=(desired_caps['udid'].replace('-', ''), event, args.verbose))
        # run the new process
        process.start()
        atexit.register(clean_up, process)
        # wait for the event to be set
        event.wait()

    t = tidevice.Device(udid=args.UDID)
    t.debug = args.verbose

    desired_caps.update({'platformVersion': t.product_version})

    while True:
        try:
            device = frida.get_device(desired_caps['udid'])
            break
        except frida.ProcessNotFoundError:
            logger.critical('frida.get_device failed. Try again...')

    if args.team_id is not None:
        if sys.platform != "darwin":
            sys.exit(f'You can\'t compile WDA on {sys.platform}!')
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
                    'usePrebuiltWDA': True,
                })
                bundle_id = [app for app in device.enumerate_applications() if app.name == WDA_CF_BUNDLE_NAME][0].identifier
                import threading
                threading.Thread(target=t.xcuitest, args=(bundle_id,), kwargs={}, daemon=True).start()
                wait_until(lambda: len([proc for proc in frida.get_usb_device().enumerate_processes() if
                                        proc.name == WDA_CF_BUNDLE_NAME]) > 0)
            except IndexError:
                sys.exit(f'{WDA_CF_BUNDLE_NAME} is not installed!')

    import anfora
    anfora.main(device, args.mjpeg)


if __name__ == '__main__':
    main()
