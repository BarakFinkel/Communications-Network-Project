from scapy.all import *

# This is a custom Scapy layer made by us in order to send information regarding the packet sent
# This will be used in order to ensure the credibility of the packet.
class RUDP(Packet):

    name = "RUDP"
    fields_desc = (
        IntField("seq_num", 0),      # the field the server uses in order to let the client know what's the serial number of the packet.
        ShortField("start_num", 32767),  # The field the server uses in order to let the client know what's the serial number of the first packet in the window.
        ShortField("end_num", 32767),    # The field the server uses in order to let the client know what's the serial number of the last packet in the window.
        ShortField("wndw_size", 0),  # The field the client sends to the server in order to set a window of un-acked packets.
        ByteField("flags",0x00),     # The field that both parties use in order to flag a type of packet they're sending. ACK = 0x01, SYN = 0x02, FIN = 0x04, NAK = 0x08
        IntField("payl_size", 0)     # The field that regards the size of the chunk of the file sent.
    )