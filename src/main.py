#!/usr/bin/env python3

import atexit
import logging
import multiprocessing
import os
import signal
import sys
import time
from datetime import date

import coloredlogs
import frida
import tidevice
from frida.core import Session, Script, ScriptExportsSync
from pymobiledevice3.services.installation_proxy import InstallationProxyService

from mirroring import clean_up, mirroring_mjpeg
from my_appium import desired_caps
from utils.anfora_utils import get_process_wrapper, clear_location

WDA_CF_BUNDLE_NAME: str = 'WebDriverAgentRunner-Runner'
EXPERIMENT_NAME: str = "SampleExperiment"

coloredlogs.install(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_options():
    """Return args parsed."""
    from utils.argparse_utils import nonempty_string, check_positive, check_team_id, ephemeral_port
    import argparse
    parser = argparse.ArgumentParser(description='PoC for AnForA on iOS devices.')
    parser.add_argument('UDID', help='the UDID of the iOS device to test', type=nonempty_string)
    parser.add_argument('-o', '--output', metavar='PATH', help='output path', type=nonempty_string,
                        required='--install-wda-only' not in sys.argv)
    parser.add_argument('--install-wda-only', action='store_true', default=False,
                        help='Use this script to (re)install WDA app')
    parser.add_argument('-b', '--bundle-id', metavar='BUNDLE_ID', help='set the bundle identifier of the installed app',
                        type=nonempty_string)
    parser.add_argument('-t', '--timeout', metavar='MINUTES', type=check_positive,
                        help='set the timeout for WebDriverAgent to become pingable (in minutes)')
    parser.add_argument('--team-id', metavar='TEAM_ID', type=check_team_id,
                        help='set the 10-character team identifier for your Apple developer account')
    parser.add_argument('-p', '--port', metavar='PORT', type=ephemeral_port, default=8100,
                        help='it will be used (by WDA app) to forward traffic from this host to real iOS devices over '
                             'USB')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--mjpeg', metavar='PORT', type=ephemeral_port, default=None, nargs='?', const=9100,
                       help='show a mirror of the screen of your iPhone using WDA MJPEG Server')
    group.add_argument('--quicktime', action='store_true', default=False,
                       help='show a mirror of the screen of your iPhone using QuickTime protocol')
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument('--location', type=float, nargs=2, metavar=('LATITUDE', 'LONGITUDE'),
                        help='provide latitude and longitude coordinates for a simulated location')
    parser.add_argument('-i', '--install', metavar='IPA_PATH', type=str, help='install a new app')
    parser.add_argument('-P', '--password', metavar='PASSWORD', type=str, default='alpine', help='mobile\'s password')
    args = parser.parse_args()
    if args.install_wda_only and args.team_id is None:
        parser.error('The --install-wda-only option requires --team-id.')
    if args.team_id is None and args.bundle_id is not None:
        parser.error('The --bundle-id option requires --team-id.')
    if args.port == args.mjpeg:
        parser.error('Port conflict.')
    return args


def handler(signum, frame):
    signame = signal.Signals(signum).name
    logger.debug(f'Signal handler called with signal {signame} ({signum})')
    if signum == signal.SIGINT:
        logger.info('Process terminated by user (Ctrl-C). Exiting with exit code 0.')
    sys.exit(0)


signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)


def main():
    args = parse_options()

    if args.team_id is not None:
        if sys.platform != "darwin":
            sys.exit(f'You can\'t compile WDA on {sys.platform}!')

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        desired_caps.update({'showIOSLog': True})

    if not args.install_wda_only:
        if args.quicktime:
            # create a shared event object
            event: multiprocessing.Event = multiprocessing.Event()
            # create a process
            from mirroring import mirroring_quicktime
            process = multiprocessing.Process(target=mirroring_quicktime,
                                              args=(args.UDID.replace('-', ''), event, args.verbose))
            # run the new process
            process.start()
            atexit.register(clean_up, process)
            # wait for the event to be set
            event.wait()

    while True:
        try:
            device = frida.get_device(args.UDID)
            break
        except frida.ProcessNotFoundError:
            logger.warning('frida.get_device failed. Try again...')

    if args.team_id is not None:
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
                bundle_id = [app for app in device.enumerate_applications() if app.name == WDA_CF_BUNDLE_NAME][0].identifier
                # TODO: a more robust solution using a custom approach + pymobiledevice3
                d = tidevice.Device(udid=args.UDID)
                d.debug = args.verbose
                d.mount_developer_image()
                del d
                desired_caps.update({
                    'useSimpleBuildTest': False,
                    'usePreinstalledWDA': True,
                    'updatedWDABundleId': bundle_id.replace('.xctrunner', ''),
                })
            except IndexError:
                sys.exit(f'{WDA_CF_BUNDLE_NAME} is not installed!')

    if not args.install_wda_only:
        # TODO: A more robust design using a SpringboardService.class.
        #  More specifically a we need to use a Singleton:
        #  https://refactoring.guru/design-patterns/singleton/python/example.
        session: Session = device.attach('Springboard')
        from anfora.anfora import springboard_ts
        script: Script = session.create_script(source=springboard_ts)
        script.load()
        api: ScriptExportsSync = script.exports_sync
        api.terminate_all_running_applications()
        # maybe equals to t.connect_instruments().app_running_processes()?
        api.turn_off_wifi()
        api.turn_on_wifi()
        if not api.get_wifi():
            sys.exit('Turn on WiFi: FAILED!')
        ssid: str
        while True:
            ssid = api.get_current_wifi_network()
            if ssid is not None:
                break
            time.sleep(.1)
        logger.info(f"iPhone is connected to {ssid}")
        session.detach()
        # TODO: check if iPhone and PC/macOS are on the same WiFi network.
        #  Another solution: change communication protocol

    desired_caps.update({
        'udid': args.UDID,
        'wdaLocalPort': args.port,
    })

    if args.timeout is not None:
        desired_caps['wdaLaunchTimeout'] = args.timeout * 1000 * 60
    if args.bundle_id is not None:
        desired_caps.update({'updatedWDABundleId': args.bundle_id})

    from pymobiledevice3.lockdown import create_using_usbmux
    lockdown = create_using_usbmux(serial=args.UDID)
    atexit.register(lockdown.close)

    desired_caps.update({'platformVersion': lockdown.product_version})

    session = device.attach('Springboard')
    from anfora.anfora import compiler, AGENT_ROOT_PATH
    frontboard_ts = compiler.build('frontboard.ts', project_root=AGENT_ROOT_PATH, compression='terser')
    script = session.create_script(source=frontboard_ts)
    script.load()
    atexit.register(lambda: session.detach())

    desired_caps.update({'mjpegServerPort': args.mjpeg})

    from anfora.anfora import init_driver
    if args.install_wda_only:
        atexit.register(lambda: device.kill(WDA_CF_BUNDLE_NAME))
    init_driver()

    if args.install_wda_only:
        exit(0)

    if args.mjpeg is not None:
        # With MJPEG server, I can't show terminateAllRunningApplications because WDA is a required app
        process = multiprocessing.Process(target=mirroring_mjpeg, args=(args.mjpeg, args.UDID,))
        process.start()
        atexit.register(clean_up, process)

    if args.install:
        if os.path.isfile(args.install):
            InstallationProxyService(lockdown=lockdown).install_from_local(args.install)
            import zipfile
            with zipfile.ZipFile(args.install) as ipa:
                info_path: str = [_ for _ in ipa.namelist() if _.startswith('Payload/') and _.endswith('.app/Info.plist')][0]
                with ipa.open(info_path) as info:
                    from plistlib import FMT_XML, load
                    pl = load(info, fmt=FMT_XML)
                    installed_bundle_id: str = pl["CFBundleIdentifier"]
            logger.info(f"{installed_bundle_id} installed!")
            atexit.register(lambda: InstallationProxyService(lockdown=lockdown).uninstall(installed_bundle_id))
        else:
            logger.critical(f"{args.install} doesn't exist or is not a file!")
            sys.exit(1)

    if args.location:
        latitude, longitude = args.location
        logger.info(f'Simulated LATITUDE: {latitude}, Simulated LONGITUDE: {longitude}')
        from pymobiledevice3.services.simulate_location import DtSimulateLocation
        DtSimulateLocation(lockdown).set(latitude, longitude)
        atexit.register(clear_location, lockdown, device)

    atexit.register(lambda: device.kill(WDA_CF_BUNDLE_NAME) if get_process_wrapper(device, WDA_CF_BUNDLE_NAME) else None)

    try:
        from anfora import anfora
        path = os.path.join(os.path.expanduser(args.output),
                            f'{EXPERIMENT_NAME}_{date.today()}_{time.strftime("%H.%M.%S", time.localtime())}')
        os.makedirs(path)
        anfora.main(device, path, lockdown, args.UDID, args.password)
    except Exception:
        import traceback
        logger.critical(traceback.format_exc())
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    if sys.platform == "linux":
        # https://stackoverflow.com/a/29558616
        multiprocessing.set_start_method('spawn')
    main()
