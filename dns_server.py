from scapy.all import *
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
# import dns.resolver
import datetime

"""
    Our DNS server holds a list of all domains previously requested by clients.
    Each domain listed in this dictionary will have a list of IP addresses associated with it, and an expiration time.
    The expiration time is the time at which the domain will be removed from the dictionary.
    This is done in a fashion whereas soon as a domain is added to the dictionary, it will be removed after 1 hour.
    This will be executed by a thread which will run in the background.
"""


# This method will be executed by a thread which will run in the background of our DNS server.
def check_ttl(dns_pool, domain_name):
    while dns_pool[domain_name][1] > datetime.datetime.now():
        time.sleep(1)
    dns_pool.pop(domain_name)


def run_dns():
    # First, we ask the server's admin to enter the device's name.
    device_name = input("Enter the name of your device: ")

    # Then we define all of our DNS server's other data.
    dns_mac = get_if_hwaddr(device_name)  # This method finds our computer's mac address.
    dns_ip = '10.0.0.11'  # The IP address of our DNS server.
    dns_port = 53  # The port on which our DNS server will listen.
    ttl = 3600  # = 1 hour (time to live)

    # This is our DNS pool. It holds all the domains and their associated IP addresses.
    # We initialize it with the domain of the app we created.
    dns_pool = {
        'www.mysterysong.com': ('localhost', datetime.datetime.now() + datetime.timedelta(seconds=ttl))
    }

    # We create a thread which will run in the background that will check if the domain's TTL has expired.
    # If it has, the domain will be removed from our DNS pool.
    thread = threading.Thread(target=check_ttl, args=(dns_pool, 'www.mysterysong.com'))
    thread.start()

    # Now, we begin a loop in which we wait for DNS query requests.
    while True:

        print("Waiting for requests...")
        request = sniff(filter=f'udp and port {dns_port} and dst host {dns_ip}', count=1, iface=device_name)  # 1 request expected
        request = request[0]

        time.sleep(1)

        req_domain = request[DNS].qd.qname.decode("utf-8")
        req_domain = req_domain[:-1] # The requested domain.

        print("Received request for domain: " + req_domain)

        """
        # If the requested domain is not in our DNS pool, we create a DNS request for it and send it
        if request[DNS].qd.qname not in dns_pool:
            resolver = dns.resolver.Resolver()  # We create a DNS resolver, that helps us find the real DNS server.
            real_dns_ip = resolver.nameservers[0]

            # We create a DNS request packet.
            ether = Ether(src=dns_mac, dst='ff:ff:ff:ff:ff:ff')
            ip = IP(src=dns_ip, dst=real_dns_ip)
            udp = UDP(sport=dns_port, dport=53)
            dnss = DNS(id=request[DNS].id, rd=1, qd=DNSQR(qname=req_domain))

            dns_request = ether / ip / udp / dnss

            # We send the DNS request packet.
            sendp(dns_request, iface=device_name)
            recv = sniff(filter=f'udp and port {dns_port}', count=1, iface=device_name)
            recv = recv[0]

            # We add the domain to our DNS pool.
            dns_pool[req_domain] = (recv[DNS].an.rdata, datetime.datetime.now() + datetime.timedelta(seconds=ttl))

            # We create a thread which will run in the background that will check if the domain's TTL has expired.
            # If it has, the domain will be removed from our DNS pool.
            thread = threading.Thread(target=check_ttl, args=(dns_pool, req_domain))
            thread.start()
        """

        if request[DNS].qd.qname not in dns_pool:
            ether = Ether(src=dns_mac, dst='ff:ff:ff:ff:ff:ff')
            ip = IP(src=dns_ip, dst=request[IP].src)
            udp = UDP(sport=dns_port, dport=request[UDP].sport)
            dnss = DNS(id=request[DNS].id, qr=1, aa=1, rcode=3, qd=request[DNS].qd,   # rcode=3 means "Name Error"
                       an=DNSRR(rrname=req_domain, ttl=ttl, rdata=None))

        # We create a response packet.
        ether = Ether(src=dns_mac, dst=request[Ether].src)
        ip = IP(src=dns_ip, dst=request[IP].src)
        udp = UDP(sport=dns_port, dport=request[UDP].sport)
        dnss = DNS(id=request[DNS].id, qr=1, qd=request[DNS].qd,
                   an=DNSRR(rrname=req_domain, ttl=ttl, rdata=dns_pool[req_domain][0]) )

        response = ether / ip / udp / dnss

        sendp(response, iface=device_name)

run_dns()