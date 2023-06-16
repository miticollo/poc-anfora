import time
from typing import Optional

from frida.core import Device


def find_available_port_in_range(start, end) -> Optional[int]:
    """
    Return the first available port in range
    :param start: starting port
    :param end: end port
    :return: port or None
    """
    for i in range(start, end, 1):
        if not is_port_in_use(i):
            return i
    return None


def is_port_in_use(port: int) -> bool:
    """Check if a port is already in use."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0


def wait_until(predicate, timeout=10, period=0.25, *args, **kwargs):
    """Return True if and only if a predicate is satisfied before timeout, False otherwise."""
    must_end = time.time() + timeout
    while time.time() <= must_end:
        if predicate(*args, **kwargs):
            return True
        time.sleep(period)
    return False


def get_process_wrapper(device: Device, process: str):
    import frida
    try:
        device.get_process(process)
        return True
    except frida.ProcessNotFoundError:
        return False
