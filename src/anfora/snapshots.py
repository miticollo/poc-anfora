import logging
import sys

import paramiko

logger = logging.getLogger(__name__)


def _run_command(client: paramiko.SSHClient, cmd: str):
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
    stdout.close()
    stderr.close()


def do_create(client: paramiko.SSHClient, snap: str, vol: str, password: str = 'alpine'):
    """
    Create snapshot.
    :param client: SSH client
    :param snap: snapshot name
    :param vol: origin FS
    :param password: mobile's password for sudo login
    """
    _run_command(client, f"echo {password} | sudo -S -p '' snaputil -c '{snap}' {vol}")


def do_delete(client: paramiko.SSHClient, snap: str, vol: str, password: str = 'alpine'):
    """
    Delete snapshot.
    :param client: SSH client
    :param snap: snapshot name
    :param vol: origin FS
    :param password: mobile's password for sudo login
    """
    _run_command(client, f"echo {password} | sudo -S -p '' snaputil -d '{snap}' {vol}")


def do_mount(client: paramiko.SSHClient, snap: str, vol: str, mntpnt: str, password: str = 'alpine'):
    """
    Mount snapshot.
    :param client: SSH client
    :param snap: snapshot name
    :param vol: origin FS
    :param mntpnt: where will snapshot be mounted?
    :param password: mobile's password for sudo login
    """
    _run_command(client, f"echo {password} | sudo -S -p '' snaputil -s '{snap}' {vol} {mntpnt}")


def do_unmount(client: paramiko.SSHClient, mntpnt: str, password: str = 'alpine'):
    """
    Unmount snapshot.
    :param client: SSH client
    :param mntpnt: where was snapshot mounted?
    :param password: mobile's password for sudo login
    """
    _run_command(client, f"echo {password} | sudo -S -p '' umount {mntpnt}")


def do_rsync(client: paramiko.SSHClient, src: str, dest: str, password: str = 'alpine'):
    """
    Revert snapshot using rsync.
    :param client: SSH client
    :param src: source path
    :param dest: destination path
    :param password: mobile's password for sudo login
    """
    _run_command(client,
                 f"echo {password} | sudo -S -p '' rsync -q -a -H -X --open-noatime -N --delete --no-W {src}/ {dest}")
