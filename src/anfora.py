import multiprocessing

from frida.core import Device
from appium.webdriver.webdriver import WebDriver

from my_appium import desired_caps, wait_for_element
from main import SERVER_URL_BASE, BUNDLE_ID, logger

global sessions
sessions = set()


def subexperiment(device: Device, driver: WebDriver, msg: str):
    spawned_pid = device.spawn([BUNDLE_ID])
    device.attach(spawned_pid, realm="native")
    device.resume(spawned_pid)
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
    pass


def main(device: Device, port: int = None):
    from appium.options.common import AppiumOptions
    from appium import webdriver
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
