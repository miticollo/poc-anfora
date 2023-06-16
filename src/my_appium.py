from typing import TYPE_CHECKING, Any, Dict, Optional, List

from selenium.common import TimeoutException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.wait import POLL_FREQUENCY

if TYPE_CHECKING:
    from appium.webdriver.webdriver import WebDriver
    from appium.webdriver.webelement import WebElement

desired_caps: Dict[str, Any] = {
    'platformName': 'iOS',
    'automationName': 'XCUITest',
    'wdaLaunchTimeout': 3 * 1000 * 60,
}

SERVER_URL_BASE: str = 'http://127.0.0.1:4723'


def wait_for_element(driver: 'WebDriver', locator: str, value: str, poll_frequency: float = POLL_FREQUENCY,
                     timeout_sec: float = 10) -> 'WebElement':
    """Wait until the element located
    Args:
        driver: WebDriver instance
        locator: Locator like WebDriver, Mobile JSON Wire Protocol
            (e.g. `appium.webdriver.common.appiumby.AppiumBy.ACCESSIBILITY_ID`)
        value: Query value to locator
        poll_frequency: Sleep interval between calls
        timeout_sec: Maximum time to wait the element. If time is over, `TimeoutException` is thrown
    Raises:
        `selenium.common.exceptions.TimeoutException`
    Returns:
        The found WebElement
    """
    return WebDriverWait(driver, timeout_sec, poll_frequency).until(EC.presence_of_element_located((locator, value)))


def wait_for_elements(driver: 'WebDriver', locator: str, value: str, poll_frequency: float = POLL_FREQUENCY,
                     timeout_sec: float = 10) -> List['WebElement']:
    """Wait until the elements located
    Args:
        driver: WebDriver instance
        locator: Locator like WebDriver, Mobile JSON Wire Protocol
            (e.g. `appium.webdriver.common.appiumby.AppiumBy.ACCESSIBILITY_ID`)
        value: Query value to locator
        poll_frequency: Sleep interval between calls
        timeout_sec: Maximum time to wait the element. If time is over, `TimeoutException` is thrown
    Raises:
        `selenium.common.exceptions.TimeoutException`
    Returns:
        The found WebElements
    """
    return WebDriverWait(driver, timeout_sec, poll_frequency).until(EC.presence_of_all_elements_located((locator, value)))


def wait_for_element_or_none(driver: 'WebDriver', locator: str, value: str, poll_frequency: float = POLL_FREQUENCY,
                             timeout_sec: float = 10) -> Optional['WebElement']:
    """Wait until the element located
    Args:
        driver: WebDriver instance
        locator: Locator like WebDriver, Mobile JSON Wire Protocol
            (e.g. `appium.webdriver.common.appiumby.AppiumBy.ACCESSIBILITY_ID`)
        value: Query value to locator
        poll_frequency: Sleep interval between calls
        timeout_sec: Maximum time to wait the element. If time is over, `TimeoutException` is thrown
    Returns:
        The found WebElement, `None` otherwise
    """
    try:
        return wait_for_element(driver, locator, value, poll_frequency, timeout_sec)
    except TimeoutException:
        return None


def wait_until_element_is_invisible(driver: 'WebDriver', element: 'WebElement', poll_frequency: float = POLL_FREQUENCY):
    """Wait until the element is invisible
    Args:
        driver: WebDriver instance
        element:
        poll_frequency: Sleep interval between calls
    """
    WebDriverWait(driver, float('inf'), poll_frequency).until(EC.visibility_of(element))
