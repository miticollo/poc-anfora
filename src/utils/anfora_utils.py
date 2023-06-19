import time
from typing import Optional

from frida.core import Device, Session, Script, ScriptExportsSync
from pymobiledevice3.services.simulate_location import DtSimulateLocation


def clear_location(lockdown, device: Device):
    """Reset location and time."""
    DtSimulateLocation(lockdown).clear()
    session: Session = device.attach('Springboard')
    from anfora.anfora import springboard_ts
    script: Script = session.create_script(source=springboard_ts)
    script.load()
    api: ScriptExportsSync = script.exports_sync
    api.toggle_airplane_mode()
    time.sleep(5)
    api.toggle_airplane_mode()
    session.detach()


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
