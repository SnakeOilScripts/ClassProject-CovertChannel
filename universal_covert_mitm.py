from scapy.all import *
from netfilterqueue import NetfilterQueue
from bitstring import BitArray
import os, argparse, sys


class CovertMITM:
    def __init__(self, dst:str, covert_message:bytes, covert_options:str):
        self.dst = dst
        self.covert_message = covert_message
        self.covert_bits = BitArray(covert_message).bin
        print("covert message: " + self.covert_bits)
        # comma-separated string specifying the type and order of data hiding technique
        self.covert_options = covert_options
        self.covert_index = 0
        self.covert_index_bits = 0
        
    def prep_firewall(self):
        os.system(f"iptables -I OUTPUT -p tcp -d {self.dst} -j NFQUEUE --queue-num 1")
    
    def unprep_firewall(self):
        os.system("iptables -D OUTPUT 1")
    
    def get_covert_bytes(self, n):
        if self.covert_index + n >= len(self.covert_message):
            ret = b''
            if self.covert_index < len(self.covert_message):
                ret += self.covert_message[self.covert_index:]
            ret += (n-len(ret)) * b'\x00'
            self.covert_index += n
            return ret
        ret = self.covert_message[self.covert_index: self.covert_index + n]
        self.covert_index += n
        return ret
    
    def get_covert_bits(self, n):
        ret = self.covert_bits[self.covert_index_bits:self.covert_index_bits+n]
        self.covert_index_bits += n
        if len(ret) < n:
            ret += '0' * (n - len(ret))
        return ret

    def packet_is_nonessential(self, packet):
        return "S" not in packet[TCP].flags and "F" not in packet[TCP].flags and "R" not in packet[TCP].flags

    def insert_covert_message(self, packet):
        # packet is a scapy IP object with lower layers
        # change values & return packet.build()
        # set checksums up for correction before changing headers
        packet[IP].chksum = None
        packet[TCP].chksum = None
        # insert arbitrary header fields for data insertion here
        for covert_option in self.covert_options.split(","):
            if covert_option == "tcp_checksum":         # wget executes no problem
                if self.packet_is_nonessential(packet):
                    msg_bits = self.get_covert_bits(16)
                    # do not zero out the checksum, as this will cause the packet to be dropped
                    if int(msg_bits, 2) != 0:
                        packet[TCP].chksum = int(msg_bits, 2)

            elif covert_option == "ip_id":              # wget executes no problem
                if self.packet_is_nonessential(packet):
                    packet[IP].id = int(self.get_covert_bits(16), 2)
                    packet[IP].chksum = None

            elif covert_option == "first_seq":          # server responds, but OS resets connection (duh, OS knows the true seq)
                if "S" in packet[TCP].flags and "A" not in packet[TCP].flags:
                    packet[TCP].seq = int(self.get_covert_bits(16), 2)
                    packet[TCP].chksum = None

            elif covert_option == "first_ack":          # wget executes no problem
                if "S" in packet[TCP].flags and "A" not in packet[TCP].flags:
                    packet[TCP].ack = int(self.get_covert_bits(32), 2)
                    packet[TCP].chksum = None

            elif covert_option == "tcp_reserved":       # wget executes no problem
                if self.packet_is_nonessential(packet):
                    packet[TCP].reserved = int(self.get_covert_bits(3), 2)

            elif covert_option == "extra_payload":      # covert message not measurable
                packet[TCP].payload += chr(int(self.get_covert_bits(8), 2)).encode()
            
            elif covert_option == "ip_checksum_1b":     # packets are dropped
                if self.packet_is_nonessential(packet):
                    packet[IP].chksum &= 0xff00
                    packet[IP].chksum |= int(self.get_covert_bits(8), 2)
            
            elif covert_option == "tcp_data_offset":    # wget finishes, but result is damaged
                if self.packet_is_nonessential(packet):
                    packet[TCP].dataofs = int(self.get_covert_bits(4), 2)

            elif covert_option == "tcp_ack_exaggeration":   # wget finishes, covert data intact, limits not tested yet
                if packet[TCP].flags == "A":
                    packet[TCP].ack += int(self.get_covert_bits(8), 2)
                
            elif covert_option == "tcp_urgent_ptr":         # wget finishes no problem
                # make sure that a real urgent pointer is not overwritten
                if packet[TCP].urgptr == 0:
                    packet[TCP].urgptr = int(self.get_covert_bits(16), 2)

            elif covert_option == "tcp_window_size":        # wget finishes no problem
                if self.packet_is_nonessential(packet):
                    # change lower byte of window size in order to not break the packet flow too muchv (avoid zeroing it out)
                    packet[TCP].window &= 0xff00
                    packet[TCP].window |= int(self.get_covert_bits(8), 2)
        return packet.build()
        
    def mainloop(self):
        def callback(pack):
            packet = IP(pack.get_payload())
            # create a new packet byte sequence based on our covert option
            packet = self.insert_covert_message(packet)
            pack.set_payload(packet)
            pack.accept()

        self.prep_firewall()
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, callback)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            print("Exiting")
            nfqueue.unbind()
            self.unprep_firewall()
    

parser = argparse.ArgumentParser()
parser.add_argument("--dest_addr", type=str)
parser.add_argument("--msg", type=str)
parser.add_argument("--method", type=str, default="tcp_checksum")

args = parser.parse_args()

if not args.dest_addr:
    print("A destination address is required for this PoC - Exiting")
    sys.exit(1)
if not args.msg:
    msg = b'\xde\xad\xc0\xde'.decode()
else:
    msg = args.msg

covertmitm = CovertMITM(args.dest_addr, msg.encode(), args.method)
covertmitm.mainloop()
