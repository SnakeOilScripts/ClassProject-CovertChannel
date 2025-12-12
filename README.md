### What is this
These scripts were part of a demonstration for a seminar class, wherein my groupmate and I created a covert channel and tested it against a free Intrusion Detection System (Suricata).
The channel would transmit patterns of very common malware, which we picked out from Suricata's community ruleset, to prove that the channel was suitable for evasion detection.
In the end, our channel proved capable of evading detection, however, data transfer got more difficult when we established a router (zeek) between sender and receiver, as the router
would edit many of the header fields used for our channel.

I wrote these PoC scripts specifically, which is why I felt at liberty of uploading them.

### How it works
Covert channels transmit data by means that are either overlooked, or very difficult to quantify to a typical IDS. Possible ways of transmitting data in a networking setting could be
timing intervals between packets (20 seconds indicating a 1, 40 seconds indicating a 0, for example), the length of a packet payload, or changes to default values in packets.
For the sake of a quick demonstration, we chose to hide data within the TCP and IPv4 packet layers, in header fields that were not essential to keep the connection alive (TCP checksum,
IP id, TCP reserved bits, TCP urgent pointer, TCP window size, and the first TCP acknowledgement number).
The threat model here would be an adversary that has root access to a system, and can use iptables and raw sockets to highjack *legitimate* connections to transfer covert data, either
to a pre-defined recipient, or to any recipient. Depending on this setting, covert messages can be received by passive sniffing on a local network, sniffing on a central access point,
or by operating a legitimate service that does not warrant suspicion, while covertly receiving messages on said service.

### Run this yourself
The sending component is in ```universal_covert_mitm.py```, which requires a message, a destination ip address, and a method as arguments. The destination ip address ensures that only packets
going to the ip address of your receiver are intercepted and altered. The method is a string representing the header fields to be used for data transfer (ip_id, first_ack, tcp_reserved,tcp_ack_exaggeration,tcp_urgent_ptr,tcp_window_size).

Once the sender is started, it waits for connections to your defined receiver. Meanwhile, on the receiver, start ```universal_covert_receiver.py```, and supply as arguments the source ip address of
your sender, the ip address of your recipient (which can also be a third system, if sniffing on the network is possible), and the same method as used for the sender.

Finally, generate some traffic from your sender to the dedicated receiver ip, for example with wget. The message should then be printed by your ```universal_covert_receiver.py```.
