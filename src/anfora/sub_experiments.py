import atexit
import time

from appium.webdriver.common.appiumby import AppiumBy
from appium.webdriver.webdriver import WebDriver
from frida.core import Device
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

from my_appium import wait_for_element, wait_for_element_or_none, wait_until_element_is_invisible, wait_for_elements


def _spawn_by_pymobiledevice(lockdown, bundle_id: str) -> int:
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        return ProcessControl(dvt).launch(bundle_id=bundle_id, kill_existing=True)


def new_contact_on_telegram(device: Device, lockdown, driver: WebDriver, bundle_id: str):
    """Create a new contact using Telegram UI."""

    def add_contact():
        element = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "Aggiungi contatto"')
        if element is not None:  # Not supported by action parser
            # For older Telegram version
            element.click()
        else:
            # TODO: add an if to support more devices
            driver.tap([(348, 71)], 500)

    spawned_pid = _spawn_by_pymobiledevice(lockdown, bundle_id)
    atexit.register(lambda: device.kill(spawned_pid))
    try:
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "OK"')
        if el is not None: # Not supported by action parser
            # Telegram has just installed!
            el.click()
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Contatti"').click()
        add_contact()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "OK"')
        if el is not None: # Not supported by action parser
            el.click()
            add_contact()
        # TODO: add an if to support more devices
        driver.tap([(177, 248)], 500)  # focus
        from selenium.webdriver.common.action_chains import ActionChains
        actions: ActionChains = ActionChains(driver)
        for digit in '393337526902':
            actions.w3c_actions.key_action.key_down(digit).key_up(digit).pause(300 / 1000)
            actions.perform()
        # TODO: add an if to support more devices
        driver.tap([(237, 131)], 500)
        for letter in 'Mario':
            actions.w3c_actions.key_action.key_down(letter).key_up(letter).pause(300 / 1000)
            actions.perform()
        # TODO: add an if to support more devices
        driver.tap([(190, 179)], 500)
        for letter in 'Rossi':
            actions.w3c_actions.key_action.key_down(letter).key_up(letter).pause(300 / 1000)
            actions.perform()
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Crea"').click()
        # We don't want to close Telegram during contact creation!
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Chiudi"').click()
    except Exception:
        raise
    finally:
        device.kill(spawned_pid)


def new_contact_on_tamtam(device: Device, lockdown, driver: WebDriver, bundle_id: str):
    """Create a new contact in TamTam using ContactUI."""
    spawned_pid = _spawn_by_pymobiledevice(lockdown, bundle_id)
    atexit.register(lambda: device.kill(spawned_pid))
    try:
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "OK"')
        if el is not None: # Not supported by action parser
            el.click()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "OK"')
        if el is not None:  # Not supported by action parser
            el.click()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "Consenti"')
        if el is not None:  # Not supported by action parser
            el.click()
        wait_for_element(driver, AppiumBy.IOS_CLASS_CHAIN,
                         '**/XCUIElementTypeTabBar[`label == "Barra pannelli"`]/XCUIElementTypeButton[1]').click()
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "ic add 24"').click()
        time.sleep(2)
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Crea contatto"').click()
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Nome"').send_keys('Luigi')
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'name == "Cognome"').send_keys('Rossi')
        # TODO: add an if to support more devices
        driver.swipe(281, 417, 281, 312)
        time.sleep(2)
        wait_for_element(driver, AppiumBy.IOS_PREDICATE,
                         'label == "aggiungi telefono" AND name == "aggiungi telefono" AND type == "XCUIElementTypeCell"').click()
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'name == "cellulare" AND value == "Telefono"').send_keys(
            '+393337526902')
        # TODO: add an if to support more devices
        driver.tap([(341, 82)], 500)
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE,
                                      'label == "Annulla" AND name == "Annulla" AND value == "Annulla"')
        if el is not None: # Not supported by action parser
            el.click()
    except Exception:
        raise
    finally:
        device.kill(spawned_pid)


def chain_of_apps(device: Device, lockdown, driver: WebDriver, bundle_id: str):
    """
    Send the current location and a message to a conversation in the TamTam app.

    Then open three apps in this order:
        1. Safari in-app
        2. App Store
        3. app-share-extension
    """
    spawned_pid = _spawn_by_pymobiledevice(lockdown, bundle_id)
    atexit.register(lambda: device.kill(spawned_pid))
    try:
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "OK"')
        if el is not None:  # Not supported by action parser
            el.click()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "OK"')
        if el is not None:  # Not supported by action parser
            el.click()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "Consenti"')
        if el is not None:  # Not supported by action parser
            el.click()
        wait_for_element(driver, AppiumBy.IOS_CLASS_CHAIN,
                         '**/XCUIElementTypeTable[`name == "OKM_CHATS_TABLE"`]/XCUIElementTypeCell[1]').click()
        time.sleep(2)
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "chat attach"')
        if el is not None:  # Not supported by action parser
            # For older TamTam version
            el.click()
        else:
            driver.find_element(by=AppiumBy.IOS_PREDICATE, value='label == "MSG_ACCESSIBILITY_CHAT_BTN_ATTACH"').click()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "Consenti l\'accesso a tutte le foto"')
        if el is not None: # Not supported by action parser
            el.click()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "OK"')
        if el is not None: # Not supported by action parser
            el.click()
        driver.find_element(by=AppiumBy.IOS_PREDICATE,
                            value='label == "Luogo" AND name == "Luogo" AND type == "XCUIElementTypeButton"').click()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "Consenti quando utilizzi l\'app"')
        if el is not None: # Not supported by action parser
            el.click()
        time.sleep(5)
        driver.find_element(by=AppiumBy.IOS_PREDICATE, value='label == "Invia posizione"').click()
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'name == "input_textview"')
        if el is not None:  # Not supported by action parser
            # For older TamTam version
            el.click()
        else:
            el = driver.find_element(by=AppiumBy.IOS_PREDICATE, value='label == "Testo messaggio"')
        el.send_keys('Hey! 👋 Do you know momentoph.com?')
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "ic send 24"')
        if el is not None:  # Not supported by action parser
            # For older TamTam version
            el.click()
        else:
            driver.find_element(by=AppiumBy.IOS_PREDICATE, value='label == "MSG_ACCESSIBILITY_CHAT_BTN_SEND"').click()
        time.sleep(2)
        wait_for_element(driver, AppiumBy.IOS_CLASS_CHAIN,
                         '**/XCUIElementTypeOther[`label == "Hey! 👋 Do you know momentoph.com?"`][1]').click()
        wait_for_element(driver, AppiumBy.IOS_CLASS_CHAIN,
                         '**/XCUIElementTypeOther[`label == "momento. | La nuova app per trovare fotografi"`]/XCUIElementTypeOther[5]/XCUIElementTypeLink').click()
        time.sleep(5)
        el = wait_for_element_or_none(driver, AppiumBy.IOS_PREDICATE, 'label == "Consenti quando utilizzi l\'app"')
        if el is not None:  # Not supported by action parser
            el.click()
        share_btn = wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Condividi"')
        share_btn.click()
        wait_for_element(driver, AppiumBy.IOS_CLASS_CHAIN,
                         '**/XCUIElementTypeCell[`label == "Viber"`]/XCUIElementTypeOther/XCUIElementTypeOther[2]').click()
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Cerca" AND name == "Cerca"').send_keys('Carl')
        contacts = wait_for_elements(driver, AppiumBy.IOS_PREDICATE, 'label == "Carl" AND name == "Carl" AND value == "Carl"')
        contacts[-1].click()
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Sì"').click()
        wait_until_element_is_invisible(driver, share_btn, poll_frequency=1.0)
    except Exception:
        raise
    finally:
        device.kill(spawned_pid)


def open_signal(device: Device, lockdown, driver: WebDriver, bundle_id: str):
    """
    Open Signal to report network privacy configuration.
    """
    from pymobiledevice3.lockdown import create_using_usbmux
    spawned_pid = _spawn_by_pymobiledevice(create_using_usbmux(serial=lockdown.identifier), bundle_id)
    # Why is necessary a new LockdownClient object?
    #  I don't know. But on Windows, a crash happens unless this new object is created.
    atexit.register(lambda: device.kill(spawned_pid))
    try:
        wait_for_element(driver, AppiumBy.IOS_CLASS_CHAIN,
                         '**/XCUIElementTypeAlert[`label == "“Signal” vorrebbe inviarti delle notifiche"`]/XCUIElementTypeOther/XCUIElementTypeOther/XCUIElementTypeOther[2]/XCUIElementTypeScrollView[1]/XCUIElementTypeOther[1]')
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Consenti"').click()
        wait_for_element(driver, AppiumBy.IOS_PREDICATE, 'label == "Consenti"').click()
    except Exception:
        raise
    finally:
        device.kill(spawned_pid)
