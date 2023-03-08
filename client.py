from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import datetime
import threading
import os


# This function will run in a separate thread and will check if the lease time has expired.
# If it has, the whole program will terminate.
def check_lease_time(lease_time):
    while lease_time > datetime.datetime.now():
        time.sleep(1)
    print("Lease time expired, please restart the program.")
    os.kill(os.getpid(), 9)


# This function is responsible for communicating with the DHCP server.
# It will send a DHCP discover packet, wait for a DHCP offer packet, and then send a DHCP request packet.
# If the DHCP server accepts the request, it will receive a DHCP ACK packet containing:
# - The IP address of the client.
# - The lease time of the IP address.
# - The IP address of the DNS server.
def get_ip(c_mac, c_port, d_port, dev_name):

    print("Broadcasting DHCP discover packet...")

    eth = Ether(src=c_mac, dst='ff:ff:ff:ff:ff:ff')
    ip = IP(src='0.0.0.0', dst='255.255.255.255')
    udp = UDP(sport=c_port, dport=d_port)
    bootp = BOOTP(chaddr=c_mac, xid=random.randint(1, 1000000000), flags=0x0000)
    dhcp = DHCP(options=[ ('message-type', 'discover'), 'end' ])
    dhcp_discover = eth / ip / udp / bootp / dhcp

    # Send the DHCP discover packet and wait for a response
    sendp(dhcp_discover, iface=dev_name)

    # Wait for a DHCP offer packet
    offer = sniff(filter=f'udp and port {c_port}', count=1, iface=dev_name)
    offer = offer[0]

    # If an offer is received, request the offered IP address
    if offer and DHCP in offer:

        offer_ip = offer[BOOTP].yiaddr
        print(f"Received DHCP offer for IP: {offer_ip}, sending DHCP request...")

        # Now, we create the DHCP request packet and send it to the DHCP server.
        eth = Ether(src=c_mac, dst='ff:ff:ff:ff:ff:ff')
        ip = IP(src='0.0.0.0', dst='255.255.255.255')
        udp = UDP(sport=c_port, dport=d_port)
        bootp = BOOTP(chaddr=c_mac, xid=random.randint(1, 1000000000), flags=0xFFFFFF)
        dhcp = DHCP(options=[ ('message-type', 'request'), ('requested_addr', offer_ip), 'end' ])
        request = eth / ip / udp / bootp / dhcp

        sendp(request, iface=dev_name)

        # Now we wait for the DHCP ACK packet
        ack = sniff(filter=f'udp and port {c_port}', count=1, iface=dev_name)
        ack = ack[0]

        # If we receive an ACK, we can use the IP address
        if ack and DHCP in ack and ack[DHCP].options[0][1] == 5:  # DHCP ACK
            lease_time = ack[DHCP].options[1][1]
            lease_time = datetime.datetime.fromtimestamp(lease_time)
            dns_server = ack[DHCP].options[2][1]

            print(f"Assigned IP address: {offer_ip} until {lease_time}")
            print(f"DNS server: {dns_server}")
            return offer_ip, lease_time, dns_server

        # If we don't receive an ACK, that meant we got a NAK. We need to start over.
        else:
            print("DHCP request FAILED.")
            return None, None, None

    # If we don't receive an offer, we need to start over.
    else:
        print("DHCP discovery FAILED.")
        return None, None, None


# This function will send a DNS query packet to the DNS server and wait for a response.
# If the DNS server responds, it will either return the IP address of the domain name requested by us,
# or it will return None if the DNS query failed.
def find_domain_ip(c_mac, c_ip, c_port, d_ip, d_port, domain):
    
    print("Finding IP address of domain name...")
    # First, we need to create a DNS query packet
    eth = Ether(src=c_mac, dst='ff:ff:ff:ff:ff:ff')
    ip = IP(src=c_ip, dst=d_ip)
    udp = UDP(sport=c_port, dport=d_port)
    dns = DNS(rd=1, qr=0 ,qd=DNSQR(qname=domain, qtype='A'))  # DNS query packet (indicated by qr=0)
    dns_request = eth / ip / udp / dns

    # Now we send the DNS query packet and wait for a response
    sendp(dns_request, iface=device_name)

    response = sniff(filter=f'udp and port {client_port}', count=1, iface=device_name)
    response = response[0]

    # If we receive a response, we check if it's a DNS response and if it contains an answer and if there wasn't a "Name Error".
    # If so, we return the IP address of the domain name.
    if response and DNS in response and (response[DNS].ancount > 0 and response[DNS].rcode != 3):
        ip_address = response[DNS].an.rdata
        print(f"IP address of '{domain}' is: {ip_address}")
        return ip_address

    # If we don't receive a response, we need to start over.
    else:
        print("DNS query failed")
        return None


# *** MAIN ***

# First, we ask the client to enter his device's name:
device_name = input("Enter your device's name: ")

# First, we define the data of our client
client_mac = str(get_if_hwaddr(device_name))  # Change if necessary
client_port = 68  # The standard port for DHCP clients
dhcp_port = 67    # The standard port for DHCP servers
client_ip_lease_time = None

# We then call the get_ip function to get an IP address
client_ip, client_ip_lease_time, dns_ip = get_ip(c_mac=client_mac, c_port=client_port,
                                                 d_port=dhcp_port, dev_name=device_name)

# Since we don't know how long the lease time is, we need to start a thread that will check if the lease time has
# expired. If it has, the whole program will terminate.
lease_checker = threading.Thread(target=check_lease_time, args=(client_ip_lease_time,))
lease_checker = lease_checker.start()

# Now we can ask the user to enter a domain name, and we will find its IP address
client_port = 20714  # The port we will use to communicate with the DNS server
dns_port = 53        # The port the DNS server will use to communicate with us

domain_name = input("Enter a domain name to find it's IP: ")

domain_ip = find_domain_ip(c_mac=client_mac, c_ip=client_ip, c_port=client_port,
                           d_ip=dns_ip, d_port=dns_port, domain=domain_name)

# Now, we will connect to the mystery song server:
server_port = 30197   # The port we will use to communicate with the mystery song server


# First, we need to create a UDP packet
