import multiprocessing

import _frida
from appium.webdriver.webdriver import WebDriver
from frida.core import Device, Session, Script

from main import SERVER_URL_BASE, BUNDLE_ID, logger
from my_appium import desired_caps, wait_for_element

global paths
paths = set()


def subexperiment(device: Device, driver: WebDriver, msg: str):
    spawned_pid = device.spawn([BUNDLE_ID])
    try:
        from appium.webdriver.common.appiumby import AppiumBy
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Carl" AND name == "Conversation list item"').click()
        el = driver.find_element(by=AppiumBy.IOS_PREDICATE, value='label == "Message input box"')
        el.click()
        el.send_keys(msg)
        driver.find_element(by=AppiumBy.IOS_PREDICATE, value='label == "Send message button"').click()
    except Exception as e:
        logger.critical(e)
        logger.critical(driver.page_source)
    device.kill(spawned_pid)


def dump():
    """Dump all paths using SCP over SSH."""
    logger.info(f'paths found: {paths}')


def child_gating_closure(device: Device):
    def on_message(message, data):
        if message["type"] == "send":
            for app_group in message["payload"]:
                paths.add(app_group['path'])
        else:
            logger.critical("Unhandled message:", message)

    def _on_child_added(child: _frida.Child):
        if child.path.startswith("/var/containers/Bundle/Application/") or child.path.startswith("/Application/"):
            paths.add(child.envp['HOME'])
            session: Session = device.attach(child.pid, realm="native")
            session.enable_child_gating()
            with open('agent/index.ts', 'r') as f:
                source = f.read()
            script: Script = session.create_script(name="AnForA", source=source)
            script.on('message', on_message)
            script.load()
            dump()
        device.resume(child.pid)

    device.on("child-added", _on_child_added)
    device.attach(1).enable_child_gating()


def main(device: Device, port: int = None):
    from appium.options.common import AppiumOptions
    from appium import webdriver

    child_gating_closure(device)

    driver: WebDriver = webdriver.Remote(SERVER_URL_BASE, options=AppiumOptions().load_capabilities(desired_caps))

    if port is not None:
        from src.mirroring import mirroring_mjpeg
        process = multiprocessing.Process(target=mirroring_mjpeg, args=(port, desired_caps['udid'],))
        process.start()
        import atexit
        from mirroring import clean_up
        atexit.register(clean_up, process)

    import datetime
    subexperiment(device, driver, f"Sub Experiment 1: {datetime.datetime.now()}")
    dump()
    subexperiment(device, driver, f"Sub Experiment 2: {datetime.datetime.now()}")

    if driver:
        driver.quit()
