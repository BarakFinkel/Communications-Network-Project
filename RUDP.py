from scapy.all import *

# This is a custom Scapy layer made by us in order to send information regarding the packet sent
# This will be used in order to ensure the credibility of the packet.
class RUDP(Packet):

    name = "RUDP"
    fields_desc = (
        IntField("seq_num", 0),      # the field the server uses in order to let the client know what's the serial number of the packet.
        IntField("ack_num", 0),      # The field the client sends in order to let the server know which packet he expects next.
        ShortField("start_num", 32767),  # The field the server uses in order to let the client know what's the serial number of the first packet in the window.
        ShortField("end_num", 32767),    # The field the server uses in order to let the client know what's the serial number of the last packet in the window.
        ShortField("wndw_size", 0),  # The field the client sends to the server in order to set a window of un-acked packets.
        ByteField("flags",0x00),     # The field that both parties use in order to flag a type of packet they're sending. ACK = 0x01, SYN = 0x02, FIN = 0x04, NAK = 0x08
        XShortField("chksm", None),  # The field that both parties use to validate the trustworthiness of the data in the packets.
        IntField("payl_size", 0)     # The field that regards the size of the chunk of the file sent.
    )

    # This is the method used in order to calculate the check-sum.
    # Here, we're using built-in method Scapy has implemented.
    def calc_checksum(self):
        pseudo_hdr = struct.pack("!HHII", self.seq_num, self.ack_num, 0, self.wndw_size)
        flags = self.flags << 9  # Shift flags to correct position
        hdr = struct.pack("!HHIHH", 0, 0, self.seq_num, self.ack_num, flags | self.wndw_size)
        data = bytes(self.payload)
        chksm = checksum(pseudo_hdr + hdr + data)
        return chksm