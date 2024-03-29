import atexit
import json
import logging
import os.path
import pathlib
import re
import sys
import tarfile
import tempfile
import threading
from datetime import datetime, timezone
from typing import Optional

import _frida
import frida
import paramiko
from frida.core import Device, Session, Script, ScriptExportsSync
from pymobiledevice3.tcp_forwarder import TcpForwarder
from appium.webdriver.webdriver import WebDriver

from anfora.snapshots import do_create, do_delete, do_mount, do_unmount, do_rsync
from anfora.sub_experiments import open_signal

logger = logging.getLogger(__name__)

driver: WebDriver

dump_paths: set = set()
rsync_paths: set = set()
internal_identifiers: set = set()
pids: set = set()

AGENT_ROOT_PATH: str = str(pathlib.Path(__file__).parent / 'agent')
MNT_POINT: str = '/mnt'

compiler: frida.Compiler = frida.Compiler()
compiler.on("diagnostics", lambda diag: logger.critical(f"on_diagnostics: {diag}"))
springboard_ts: str = compiler.build('springboard.ts', project_root=AGENT_ROOT_PATH, compression='terser')


def reset_iphone(api: ScriptExportsSync):
    """Reset like Settings > General > Reset > Reset Location & Privacy."""
    api.reset_all_app_tcc_permissions()
    api.reset_all_app_location_permission()
    api.reset_all_app_notification_permissions()
    api.reset_all_app_ne_permissions()
    for internal_identifier in internal_identifiers:
        api.remove_contact_by_internal_identifier(internal_identifier)
    internal_identifiers.clear()


def kill_all_processes(device: Device, spawn_thread: threading.Thread, pcap_thread: Optional[threading.Thread], stop_event: threading.Event):
    stop_event.set()
    if spawn_thread.is_alive():
        spawn_thread.join()
    logger.info('spawn_thread stopped!')
    if pcap_thread is not None and pcap_thread.is_alive():
        pcap_thread.join()
    logger.info('pcap_thread stopped!')
    for pid in pids:
        device.kill(pid)
        logger.info(f'Killed {pid}!')
    pids.clear()


def pull_extract_tar(client: paramiko.SSHClient, paths: set, password: str, destination: str):
    temp_tar_file_path = pathlib.Path(tempfile.gettempdir(), "AnForA_DUMP_TMP.tar")
    # based on https://stackoverflow.com/a/32758464 and
    # https://github.com/paramiko/paramiko/issues/593#issuecomment-145377328
    with open(temp_tar_file_path, "wb") as fdout:
        names: str = ' '.join(f"'{path}'" for path in paths)
        # TODO: how to handle symlinks on Windows?
        #  At the moment symlinks are not dereference because there is a loop in TamTam Data container.
        tar_cmd = "tar -cf - --xattrs --hard-dereference "
        if next(iter(paths)).startswith(MNT_POINT):
            tar_cmd += f"-P --transform='s,^{MNT_POINT},private/var,' "
        if os.name == 'nt':
            # https://stackoverflow.com/a/31976060
            tar_cmd += "--transform='s/[:*?\\\\\"<>|]/_/g' "
        else:
            # A symbolic link doesn't work on Windows
            tar_cmd += f"--transform='s,^,{destination},RH' "
        tar_cmd += f"{names}"
        # one channel per command
        stdin, stdout, stderr = client.exec_command(f"stty raw; echo {password} | sudo -S -p '' {tar_cmd}")
        # get the shared channel for stdout/stderr/stdin
        channel = stdout.channel
        # we do not need stdin.
        stdin.close()
        # indicate that we're not going to write to that channel anymore
        channel.shutdown_write()
        while read_bytes := stdout.read(4096):
            fdout.write(read_bytes)
        # indicate that we're not going to read from this channel anymore
        channel.shutdown_read()
        # close the channel
        stdout.channel.close()
        # close all the pseudofiles
        stdout.close()
        stderr.close()

    my_tar = tarfile.open(fdout.name, mode="r:")
    my_tar.extractall(destination)
    my_tar.close()
    if temp_tar_file_path.is_file():
        temp_tar_file_path.unlink()


def dump_metadata(client: paramiko.SSHClient, parent_path: str, paths: set):
    names: str = ' '.join(f"'{path}'" for path in paths)
    # TODO: missing extended attributes?
    cmd: str = f"find {names} ! -type l -print0 | xargs -0 stat -c '%n:::%f:::%u:::%g:::%s:::%X:::%Y:::%Z'"
    if next(iter(paths)).startswith(MNT_POINT):
        cmd += f" | sed -E 's,^{MNT_POINT},/private/var,gm;t;d'"
    stdin, stdout, stderr = client.exec_command(cmd)
    channel = stdout.channel
    stdin.close()
    channel.shutdown_write()
    exit_status: int = channel.recv_exit_status()
    if exit_status == -1:
        logger.critical('No exit status is provided by the server, -1 is returned!')
        sys.exit(1)
    elif channel.recv_stderr_ready():
        logger.critical(stderr.read().decode("utf-8"))
        sys.exit(1)
    channel.shutdown_read()
    channel.close()
    stderr.close()
    # TODO: convert into CSV
    with open(os.path.join(parent_path, 'metadata.csv'), 'x') as fdout:
        fdout.write(stdout.read().decode("utf-8"))
    stdout.close()


def dump(client: paramiko.SSHClient, name: str, parent_path: str, password: str):
    """
    Dump all paths using SCP over SSH.

    Dumps are always done AFTER sub-experiments. While snapshots are always done BEFORE sub-experiments.
    In this way, we use the snapshot to do the dump BEFORE sub-experiment.
    """
    first_dump: str = os.path.join(parent_path, f'{name}_FIRST_DUMP')
    last_dump: str = os.path.join(parent_path, f'{name}_LAST_DUMP')
    os.makedirs(first_dump)
    snapshot_paths: set = {re.sub(r'(/private)?/var', MNT_POINT, path) for path in dump_paths}
    logger.info(f'Dumping from snapshot...')
    do_mount(client, 'anfora', '/var', MNT_POINT, password)
    try:
        dump_metadata(client, first_dump, snapshot_paths)
        pull_extract_tar(client, snapshot_paths, password, first_dump)
    except Exception as e:
        raise e
    finally:
        do_unmount(client, MNT_POINT, password)
        do_delete(client, 'anfora', '/var', password)
    logger.info(f'Dumping from FS...')
    dump_metadata(client, last_dump, dump_paths)
    pull_extract_tar(client, dump_paths, password, last_dump)
    dump_paths.clear()


def detect_analysis_paths(process: _frida.Process, _paths: set):
    logger.info(f"""
Detect analysis paths:
    process = {process.name} (PID {process.pid}) 
    paths = {_paths}""")
    dump_paths.update(_paths)
    rsync_paths.update(_paths)
    pids.add(process.pid)


def garbage(process: _frida.Process):
    """
    Collect all processes that don't require a dump.

    All Mach-O files under /System/Library/Frameworks/ don't have a container.
    But I want to report their spawn and then kill them.
    """
    logger.info(f"""
New (garbage) process spawned:
    process = {process.name} (PID {process.pid})""")
    pids.add(process.pid)


def report_query_on_tcc_db(process: _frida.Process, payload: []):
    _path: str = "/private/var/mobile/Library/TCC/"
    logger.info(f"""
INSERT or REPLACE in {_path} (`tccd` SQLite DB):
    service = {payload[0]}
    client = {payload[1]} (PID {process.pid})
    auth_value = {payload[3]}""")
    dump_paths.update({_path})
    pids.add(process.pid)


def report_contact_crud_op(process: _frida.Process, payload: str):
    _path: str = "/private/var/mobile/Library/AddressBook/"
    logger.info(f"""
CRUD operation on {_path} (`contactsd` SQLite DB):
    process = {process.name} (PID {process.pid})
    _internalIdentifier = {payload}""")
    internal_identifiers.add(payload)
    dump_paths.update({_path})
    # Some process doesn't have a container (e.g., ContactUI.framework).
    # So we store its PID because the function detect_analysis_paths is never triggered.
    pids.add(process.pid)


def report_keychain_crud_op(process: _frida.Process, payload, data: Optional[bytes]):
    _path: str = "/private/var/Keychains/"
    # I add local datetime to compare timestamp in Keychain DB.
    # Time format: [Apple Cocoa Core Data timestamp](https://www.epochconverter.com/coredata)
    msg: str = f"""
{payload['op']} on {_path} (`securityd` SQLite DB):
    process = {process.name} (PID {process.pid})
    datetime (in local timezone) = {datetime.now(timezone.utc).astimezone().isoformat()}
    query = {json.dumps(payload['query'], indent=6)}"""
    if payload['op'] == 'SecItemUpdate':
        msg += f"""
    attributesToUpdate = {json.dumps(payload['attributesToUpdate'], indent=6)}"""
    if data is not None:
        # TODO: improve results presentation
        msg += f"""
    kSecValueData = {data}"""
    logger.info(msg)
    dump_paths.update({_path})
    # See report_contact_crud_op
    pids.add(process.pid)


def report_new_notification_permission(process: _frida.Process, payload: str):
    _path: str = "/private/var/mobile/Library/BulletinBoard/VersionedSectionInfo.plist"
    logger.info(f"""
New key-value pair added to {_path}:
    process = {process.name} (PID {process.pid})
    BBSectionInfoSettings = {payload}""")
    dump_paths.update({_path})
    pids.add(process.pid)


def report_change_on_ne_configuration(configuration: str):
    _path: str = "/private/var/preferences/com.apple.networkextension.plist"  # TODO: I'm not sure
    logger.info(f"""
A changing happens in NEConfiguration at ?? (`nehelper` ??):
    configuration = {json.dumps(configuration, indent=6)}""")


def reset_to_cleanup_backup(api: ScriptExportsSync, client: paramiko.SSHClient, password: str):
    if client._transport is not None:
        api.turn_on_airplane_mode()
        do_mount(client, 'CLEAN_BACKUP', '/var', MNT_POINT, password)
        for path in rsync_paths:
            src: str = re.sub(r'(/private)?/var', MNT_POINT, path)
            dest: str = path
            do_rsync(client, src, dest, password)
        do_unmount(client, MNT_POINT, password)
        # TODO: Which are reverts missing? Cookies, other permissions, new photos, etc...
        #  Almost surely Keychain queries MUST be reverted but how?
        #  If you try to remove all items for a specific app (e.g., Session) you also must reinstall it.
        #  Because it can't open DB given that the password is removed by SecItemDelete.
        reset_iphone(api)
        api.turn_off_airplane_mode()
        rsync_paths.clear()


def init_driver():
    from appium import webdriver
    from my_appium import SERVER_URL_BASE, desired_caps

    # To install the WDA app on iOS 16.4+ Xcode 14.3+ is required.
    # Anyway, this version is not suitable for iOS 12 and 13.
    # As reported here: https://stackoverflow.com/q/76156478

    # Furthermore, iOS 12, 13 & 14 are supported up to the version 4.30.9 of appium-xcuitest-driver.
    # Starting from version 4.31.0, the driver depends on version 5.4.0 of WebDriverAgent.
    # This version drops older screenshotting APIs, breaking backward compatibility with iOS <= 14 (see also
    # https://github.com/appium/WebDriverAgent/pull/721/files#r1222509149).
    # I tried to use the latest version of appium-xcuitest-driver with an older appium-webdriveragent, but it doesn't work.
    # It seems that appium-xcuitest-driver "forces" the use of its version of WDA app.

    # To install the WDA app on iOS 14, you can use Xcode up to version 14.x.y.
    global driver
    driver = webdriver.Remote(SERVER_URL_BASE, desired_capabilities=desired_caps)
    atexit.register(lambda: driver.quit() if driver else None)


def main(device: Device, path: str, lockdown, udid: str, password: str = 'alpine'):
    from utils.anfora_utils import find_available_port_in_range

    session: Session = device.attach('Springboard')
    script: Script = session.create_script(source=springboard_ts)
    script.load()
    api: ScriptExportsSync = script.exports_sync

    reset_iphone(api)

    port: int = find_available_port_in_range(1025, 40000)

    forwarder = TcpForwarder(port, 22, serial=udid)
    threading.Thread(target=forwarder.start, args=(), kwargs={}, daemon=True).start()
    atexit.register(forwarder.stop)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    logger.info(f'SSH connection over USB using port-forwarding localhost:{port}')
    client.connect('localhost', port=port, username='mobile', password=password)

    stop_event: threading.Event = threading.Event()
    from anfora.spawn_thread import spawn_thread_closure
    from anfora.pcap import pcap

    spawn_thread: threading.Thread = threading.Thread(target=spawn_thread_closure, args=(device, stop_event,), kwargs={})
    atexit.register(session.detach)
    atexit.register(api.terminate_all_running_applications)
    atexit.register(kill_all_processes, device, spawn_thread, None, stop_event)

    from anfora.sub_experiments import new_contact_on_telegram, new_contact_on_tamtam, chain_of_apps

    do_create(client, 'CLEAN_BACKUP', '/var', password)

    try:
        print("""
###################################
#                                 # 
#     New contact on Telegram     #
#                                 #
###################################
""")

        do_create(client, 'anfora', '/var', password)

        driver.unlock()     # TODO: workaround because I couldn't disable lockscreen timeout
        spawn_thread.start()
        sub_experiment_name: str = '0_new_contact_on_telegram'
        pcap_thread: threading.Thread = threading.Thread(target=pcap,
                                                         args=(lockdown, sub_experiment_name, path, stop_event,), kwargs={})
        pcap_thread.start()
        new_contact_on_telegram(device, lockdown, driver, 'ph.telegra.Telegraph')
        kill_all_processes(device, spawn_thread, pcap_thread, stop_event)

        dump(client, sub_experiment_name, path, password)

        api.turn_on_bluetooth()

        print("""
###################################
#                                 # 
#      New contact on TamTam      #
#                                 #
###################################
""")

        do_create(client, 'anfora', '/var', password)

        spawn_thread = threading.Thread(target=spawn_thread_closure, args=(device, stop_event,), kwargs={})

        driver.unlock()     # TODO: workaround because I couldn't disable lockscreen timeout
        spawn_thread.start()
        sub_experiment_name = '1_new_contact_on_tamtam'
        pcap_thread: threading.Thread = threading.Thread(target=pcap,
                                                         args=(lockdown, sub_experiment_name, path, stop_event,), kwargs={})
        pcap_thread.start()
        new_contact_on_tamtam(device, lockdown, driver, 'ru.odnoklassniki.messenger')
        kill_all_processes(device, spawn_thread, pcap_thread, stop_event)

        dump(client, sub_experiment_name, path, password)

        reset_to_cleanup_backup(api, client, password)

        print("""
####################################
#                                  # 
#           Chain of App           #
#                                  #
####################################
""")

        do_create(client, 'anfora', '/var', password)

        spawn_thread = threading.Thread(target=spawn_thread_closure, args=(device, stop_event,), kwargs={})

        driver.unlock()     # TODO: workaround because I couldn't disable lockscreen timeout
        spawn_thread.start()
        sub_experiment_name = '2_chain_of_apps'
        pcap_thread: threading.Thread = threading.Thread(target=pcap,
                                                         args=(lockdown, sub_experiment_name, path, stop_event,), kwargs={})
        pcap_thread.start()
        chain_of_apps(device, lockdown, driver, 'ru.odnoklassniki.messenger')
        kill_all_processes(device, spawn_thread, pcap_thread, stop_event)

        dump(client, sub_experiment_name, path, password)

        api.turn_off_bluetooth()

        print("""
###################################
#                                 # 
#           Open Signal           #
#                                 #
###################################
""")

        do_create(client, 'anfora', '/var', password)

        spawn_thread = threading.Thread(target=spawn_thread_closure, args=(device, stop_event,), kwargs={})

        driver.unlock()  # TODO: workaround because I couldn't disable lockscreen timeout
        spawn_thread.start()
        sub_experiment_name = '3_open_signal'
        pcap_thread: threading.Thread = threading.Thread(target=pcap,
                                                         args=(lockdown, sub_experiment_name, path, stop_event,), kwargs={})
        pcap_thread.start()
        open_signal(device, lockdown, driver, 'org.whispersystems.signal')
        kill_all_processes(device, spawn_thread, pcap_thread, stop_event)

        dump(client, sub_experiment_name, path, password)

        # EOE (End-Of-Experiment)
    except Exception as e:
        raise e
    finally:
        reset_to_cleanup_backup(api, client, password)

        do_delete(client, 'CLEAN_BACKUP', '/var', password)

    if client:
        client.close()
