import atexit
import multiprocessing

from ioscreen.util import init_logger, find_ios_device, record_gstreamer, iPhoneModels
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.tcp_forwarder import TcpForwarder


# define a function to terminate process
def clean_up(process: multiprocessing.Process):
    if process is not None and process.is_alive():
        process.kill()


def mirroring_quicktime(udid: str, event: multiprocessing.Event, verbosity: bool):
    import usb
    init_logger(verbosity)
    device: usb.Device = find_ios_device(udid)
    record_gstreamer(device, event)


def mirroring_mjpeg(port: int, udid: str):
    import mpv
    import threading

    from PyQt5.QtWidgets import QMainWindow, QWidget, QApplication
    from PyQt5.QtCore import Qt

    d = create_using_usbmux(serial=udid)

    class Test(QMainWindow):

        def __init__(self, parent=None):
            super().__init__(parent)
            self.container = QWidget(self)
            self.setWindowTitle(f'{iPhoneModels.get_model(d.product_type)} ({d.udid})')
            self.setFixedSize(iPhoneModels.get_width(d.product_type), 942)
            self.setCentralWidget(self.container)

            self.container.setAttribute(Qt.WA_DontCreateNativeAncestors)
            self.container.setAttribute(Qt.WA_NativeWindow)
            player = mpv.MPV(wid=str(int(self.container.winId())),
                             demuxer_lavf_format='mjpeg',
                             profile='low-latency',
                             untimed=True)
            player.play(f'http://localhost:{port}')

    app = QApplication([])

    forwarder = TcpForwarder(port, port, serial=udid)
    threading.Thread(target=forwarder.start, args=(), kwargs={}, daemon=True).start()
    atexit.register(forwarder.stop)

    import locale

    locale.setlocale(locale.LC_NUMERIC, 'C')
    win = Test()
    win.show()

    import sys
    sys.exit(app.exec())
