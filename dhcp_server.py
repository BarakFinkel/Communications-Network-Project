from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import datetime


# The function to run our server:
def run_dhcp():
    
    # First, we ask the server's admin to enter the device's name.
    device_name = input("Enter the device's name: ")
    
    # First, we define the data of our DHCP server
    dhcp_ip = '10.0.0.10'  # The IP address of our DHCP server.
    dns_ip = '10.0.0.11'
    dhcp_port = 67
    dhcp_mac = str(get_if_hwaddr(device_name))  # This method finds our computer's mac address. (change if necessary)
    time_to_lease = 86400  # = 1 day

    dhcp_pool = {  # The pool of addresses which we lease to our clients.
        '10.0.0.13': datetime.datetime.now(),
        '10.0.0.14': datetime.datetime.now(),
        '10.0.0.15': datetime.datetime.now()
    }

    while True:
        # Now, we wait to sniff a request.
        print("Waiting for packets...")
        client_packet = sniff(filter=f'udp and port {dhcp_port}', count=1, iface=device_name)  # 1 request expected
        client_packet = client_packet[0]  # Get the first packet in the list

        time.sleep(1)

        # If we sniffed a DHCP packet:
        if client_packet and DHCP in client_packet:

            # We read the client's request into the following variables:

            client_mac = client_packet[Ether].src  # We copy the client's mac address.
            client_opt = client_packet[DHCP].options[1:-1]  # We copy everything from the client's requested options.
            client_xid = client_packet[BOOTP].xid  # We copy the ID of the packet.
            client_port = client_packet[UDP].sport  # We copy the client's port.

            # Now, we will enter the if statement below only if we caught a DHCP request.
            # For each type: broadcast or request, we handle the package differently.

            # If we get a broadcast DHCP packet:
            if client_packet[DHCP].options[0][1] == 1:

                print(f"Sniffed a discovery packet from: {client_mac}")

                # Now, we loop through the pool and add any unused IPs to a list.
                # Therefore, if the IP's lease time has expired, we will add it to the list.
                open_ips = []
                for (ip, lt) in dhcp_pool.items():
                    if lt is None or lt < datetime.datetime.now():
                        open_ips.append(ip)

                # If there are no IP addresses available, we don't answer the broadcast and try to catch the next
                # DHCP packet.
                if not open_ips:
                    print("No available IPs. Ignoring and moving on...")
                    print("")
                    continue

                # If there are, then we take the first available IP, and assign a date of expiration to it.
                # We save that exp. date in our DHCP pool and prepare to send it to the client.
                client_ip = open_ips[0]

                print("Sending DHCP offer with IP: " + client_ip + " to client")

                # Now, we create the DHCP offer packet:
                eth = Ether(src=dhcp_mac, dst=client_mac)
                ip = IP(src=dhcp_ip, dst='255.255.255.255')
                udp = UDP(sport=dhcp_port, dport=client_port)
                bootp = BOOTP(op=2, yiaddr=client_ip, siaddr=dhcp_ip, chaddr=client_mac, xid=client_xid)
                dhcp = DHCP(options=[('message-type', 'offer'),
                                     ('subnet_mask', '255.255.255.0'),
                                     ('router', dhcp_ip),
                                     'end'])

                dhcp_offer = eth / ip / udp / bootp / dhcp

                # We are ready to send the DHCP offer packet to the client!
                sendp(dhcp_offer, iface=device_name)

            # If we get a request DHCP packet:
            elif client_packet[DHCP].options[0][1] == 3:

                print(f"Sniffed a request packet from: {client_mac}")
                # Now, we search through the options given by the client and try to determine if he requested IP
                # address.
                request_ip = None
                for option in client_opt:
                    if option[0] == 'requested_addr':
                        request_ip = option[1]
                        break

                client_ip = None
                client_lease_until = None

                # Afterwards, if we found such address, and it's in our pool and available for allocation, we prepare
                # and offer message.
                if request_ip and (request_ip in dhcp_pool) and (datetime.datetime.now() > dhcp_pool[request_ip]):

                    client_ip = request_ip
                    client_lease_until = datetime.datetime.now() + datetime.timedelta(seconds=time_to_lease)
                    dhcp_pool[request_ip] = client_lease_until

                    print(f"Client requested {request_ip}. Status: Available.")
                    print(f"Assigning to client until: {client_lease_until} and sending ACK packet...")

                    # Now, we create the DHCP offer packet:
                    eth = Ether(src=dhcp_mac, dst=client_mac)
                    ip = IP(src=dhcp_ip, dst='255.255.255.255')
                    udp = UDP(sport=dhcp_port, dport=client_port)
                    bootp = BOOTP(op=2, yiaddr=client_ip, siaddr=dhcp_ip, chaddr=client_mac, xid=client_xid)
                    dhcp = DHCP(options=[('message-type', 'ack'),
                                         ('lease_time', int(client_lease_until.timestamp())),
                                         ('name_server', dns_ip),  # This way, we send the client the DNS server's IP.
                                         'end'])

                    dhcp_ack = eth / ip / udp / bootp / dhcp

                    # We are ready to send the DHCP offer packet to the client!
                    sendp(dhcp_ack)
                    print("ACK packet sent successfully!")
                    print("")

                # Else, it means either the client sent an invalid address or it's not available. Therefore,
                # we sent a nak - meaning we reject the client's request.
                else:

                    print(f"Client requested {request_ip}. Status: Unavailable.")
                    print("Sending a NAK packet...")

                    eth = Ether(src=dhcp_mac, dst=client_mac)
                    ip = IP(src=dhcp_ip, dst='255.255.255.255')
                    udp = UDP(sport=dhcp_port, dport=client_port)
                    bootp = BOOTP(op=2, yiaddr='0.0.0.0', siaddr=dhcp_ip, chaddr=client_mac, xid=client_xid)
                    dhcp = DHCP(options=[('message-type', 'nak'), 'end'])

                    dhcp_nak = eth / ip / udp / bootp / dhcp

                    # We are ready to send the DHCP offer packet to the client!
                    sendp(dhcp_nak)

                    print("NAK packet sent successfully!")
                    print("")


run_dhcp()
