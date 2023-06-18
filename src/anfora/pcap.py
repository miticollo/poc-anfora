import os
import struct
import threading

from pymobiledevice3.services.pcapd import PcapdService, PCAP_HEADER, PACKET_HEADER


def pcap(lockdown, name: str, parent_path: str, stop_event: threading.Event):
    """ sniff device traffic """

    def write_to_pcap(out, packet_generator):
        out.write(PCAP_HEADER)
        for packet in packet_generator:
            length = len(packet.data)
            pkthdr = struct.pack(PACKET_HEADER, packet.seconds, packet.microseconds, length, length)
            data = pkthdr + packet.data
            out.write(data)
            if stop_event.wait(.1):
                break

    service = PcapdService(lockdown=lockdown)
    packets_generator = service.watch()
    last_dump: str = os.path.join(parent_path, f'{name}_LAST_DUMP')
    os.makedirs(last_dump)
    with open(os.path.join(last_dump, 'dump.pcap'), 'x+b') as fdout:
        write_to_pcap(fdout, packets_generator)
    service.close()
