from scapy.all import *
from bitstring import BitArray
import os, socket, sys, argparse

class CovertReceiver:

    def __init__(self, src:str, dst:str=None, covert_options:str=""):
        self.src = src
        self.covert_options = covert_options
        self.dst = dst
        self.covert_message_bits = ""


    def mainloop(self):
        sniff(prn=self.packet_callback, filter=f"tcp and src host {self.src} and dst host {self.dst}", store=0)


    def packet_is_nonessential(self, packet):
        return "S" not in packet[TCP].flags and "F" not in packet[TCP].flags and "R" not in packet[TCP].flags


    def packet_callback(self, packet):
        print("received packet")
        print("current msg: {" + self.covert_message_bits + "}")
        for option in self.covert_options.split(","):
            if option == "tcp_checksum":
                if self.packet_is_nonessential(packet):
                    checksum = packet[TCP].chksum
                    self.covert_message_bits += '{0:016b}'.format(checksum)
            elif option == "ip_id":
                if self.packet_is_nonessential(packet):
                    ip_id = packet[IP].id
                    self.covert_message_bits += '{0:016b}'.format(ip_id)
            elif option == "first_ack":
                if 'S' in packet[TCP].flags and 'A' not in packet[TCP].flags:
                    ack = packet[TCP].ack
                    self.covert_message_bits += '{0:032b}'.format(ack)
            elif option == "tcp_reserved":
                if self.packet_is_nonessential(packet):
                    reserved = packet[TCP].reserved
                    self.covert_message_bits += '{0:04b}'.format(reserved)
            elif option == "tcp_urgent_ptr":
                if packet[TCP].urgptr == 0:
                    urg = packet[TCP].urgptr
                    self.covert_message_bits += '{0:016b}'.format(urg)
            elif option == "tcp_window_size":
                if self.packet_is_nonessential(packet):
                    window = packet[TCP].window
                    window &= 0x00ff
                    self.covert_bits += '{0:08b}'.format(window)
            elif option == "tcp_ack_exaggeration":
                pass

parser = argparse.ArgumentParser()
parser.add_argument("--dst_addr", type=str)
parser.add_argument("--src_addr", type=str)
parser.add_argument("--method", type=str, default="tcp_checksum")

args = parser.parse_args()
if not args.dst_addr:
    print("The destination address supplied to universal_covert_mitm.py is required as dst_addr argument to this PoC - exiting")
    sys.exit(1)
elif not args.src_addr:
    print("The IP address of the machine running the universal_covert_mitm.py script is required as src_addr argument for this PoC - exiting")
    sys.exit(1)

receiver = CovertReceiver(args.src_addr, args.dst_addr, args.method)

try:
    receiver.mainloop()
except KeyboardInterrupt:
    print(receiver.covert_message_bits)