import os
import struct
import threading
from typing import Generator

from construct import Container
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.pcapd import PcapdService, PCAP_HEADER, PACKET_HEADER, device_packet_struct, \
    ETHERNET_HEADER, INTERFACE_NAMES


class PcapdServiceForAnfora(PcapdService):
    def watch(self, stop_event: threading.Event = None, _=None) -> Generator[Container, None, None]:
        while True:
            d = self.service.recv_plist()
            if not d:
                break

            packet = device_packet_struct.parse(d)

            if not packet.frame_pre_length:
                packet.data = ETHERNET_HEADER + packet.data
            packet.interface_type = INTERFACE_NAMES(packet.interface_type)
            # packet.protocol_family = socket.AddressFamily(packet.protocol_family) # comment to avoid Windows error

            yield packet

            if stop_event.wait(.1):
                break


def pcap(lockdown, name: str, parent_path: str, stop_event: threading.Event):
    """ sniff device traffic """

    def write_to_pcap(out, packet_generator):
        out.write(PCAP_HEADER)
        for packet in packet_generator:
            length = len(packet.data)
            pkthdr = struct.pack(PACKET_HEADER, packet.seconds, packet.microseconds, length, length)
            data = pkthdr + packet.data
            out.write(data)

    pcap_lockdown = create_using_usbmux(serial=lockdown.identifier)  # Why? Otherwise, a runtime error occurred!
    service = PcapdServiceForAnfora(lockdown=pcap_lockdown)
    packets_generator = service.watch(stop_event)
    last_dump: str = os.path.join(parent_path, f'{name}_LAST_DUMP')
    os.makedirs(last_dump)
    with open(os.path.join(last_dump, 'dump.pcap'), 'x+b') as fdout:
        write_to_pcap(fdout, packets_generator)
    service.close()
    pcap_lockdown.close()
    del service
    del pcap_lockdown
