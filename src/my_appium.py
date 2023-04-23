from typing import TYPE_CHECKING, Any, Dict

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


def wait_for_element(driver: 'WebDriver', locator: str, value: str, timeout_sec: float = 10) -> 'WebElement':
    """Wait until the element located
    Args:
        driver: WebDriver instance
        locator: Locator like WebDriver, Mobile JSON Wire Protocol
            (e.g. `appium.webdriver.common.appiumby.AppiumBy.ACCESSIBILITY_ID`)
        value: Query value to locator
        timeout_sec: Maximum time to wait the element. If time is over, `TimeoutException` is thrown
    Raises:
        `selenium.common.exceptions.TimeoutException`
    Returns:
        The found WebElement
    """
    return WebDriverWait(driver, timeout_sec).until(EC.presence_of_element_located((locator, value)))
