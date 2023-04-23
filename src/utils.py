import argparse
import time


def nonempty_string(value):
    """Return the input value if it is not an empty string."""
    if not value:
        raise argparse.ArgumentTypeError('Empty string found.')
    return value


def check_positive(value):
    """Return the input value as int if a positive integer."""
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise argparse.ArgumentTypeError(f'{value} is not a positive integer.')
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f'Can\'t cast `{value}` to a positive integer.')


def ephemeral_port(value):
    """Return the input value if a valid open ephemeral port"""
    if value is None:
        return value
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a valid integer value.")

    if not (1024 <= port <= 65535):
        raise argparse.ArgumentTypeError(f"{port} is not a valid ephemeral port.")

    if is_port_in_use(port):
        raise argparse.ArgumentTypeError(f"{port} is already in use.")

    return port


def is_port_in_use(port: int) -> bool:
    """Check if a port is already in use."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0


def check_team_id(value):
    """Return true if the input value is a valid Team ID, false otherwise."""
    up = str.upper(value)
    import re
    if not re.match(r'^[A-Z0-9]{10}$', up):
        raise argparse.ArgumentTypeError('Team ID must be a 10-character string of uppercase letters and numbers.')
    return up


def wait_until(predicate, timeout=10, period=0.25, *args, **kwargs):
    """Return true if and only if a predicate is satisfied before timeout, false otherwise."""
    must_end = time.time() + timeout
    while time.time() <= must_end:
        if predicate(*args, **kwargs):
            return True
        time.sleep(period)
    return False
