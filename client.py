from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import datetime
import threading
import os
import socket
from urllib.parse import urlparse
from RUDP import RUDP

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


# This function is for communicating with the mystery_song_server. 
# The function tries to create a tcp connection with the server, 
# and if is succussful, so it send an http reqeuset asking the wanted name of song
# The function then receives the location where the song is. 
#  


def request_song(songname, host, srv_port):
  
    try:
        # create TCP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # set a timeout for the connection attempt
        client_socket.settimeout(4.0)
        
        # connect to server
        client_socket.connect((host, srv_port))

        # create request with songname
        request = f"GET /{songname} HTTP/1.1\r\nHost: {HOST}\r\n\r\n"

        # send request to server
        client_socket.sendall(request.encode())

        # receive response from server - The location of the song
        response = client_socket.recv(1024)
        
        # find the location of the song 
        response_str = response.decode('utf-8')
        if 'HTTP/1.1 301' in response_str:
            location_start = response_str.find('Location: ') + len('Location: ')
            location_end = response_str.find('\r\n', location_start)
            location = response_str[location_start:location_end]
            print(f'Redirect location {location}')

        else:
            location = None 


        # close connection
        client_socket.close()
        
        #return the location 
        return location
    
    except(socket.error, socket.timeout, socket.gaierror, ConnectionRefusedError) as e: 
        print(f'An error occured: {e}')


# This function is for communicating with the proxy server, to get a song suggestion for download.
# The function tries to create a tcp connection with the server,
# and if is succussful, so it send an http reqeuset asking for a song suggestion
# The function then receives the name of the song suggested.

def request_suggestion(host, srv_port):
    # choose genre
    song_genre = input("Enter the genre of the song that you wish to download:  1 - Pop   2 - Hip Hop   3 - Rock : ")

    # choose language
    song_language = input("Enter the language of the song that you want to download:  A - English, B - Hebrew, C - French, D - Italian : ")

    # format request
    song_requested = f'{song_genre}-{song_language}'

    # send request
    location = request_song(song_requested, host, srv_port) 

    # found song - go to download it 
    if location:
        return location

    # no such song. try again? 
    else:
        return None
        print("no such song")   


# This method is responsible for making the initial connection between the client and the server.
# It does so by sending a SYN packet from the client, and then receiving a SYN-ACK packet from the server.
# The client then send an ACK packet back to the server, and the connection is established.
# Afterwards, the client gets ready to receive packets from the client.
def initial_connection(clnt_mac, srv_port, clnt_port, srv_ip, clnt_ip, song_request):

    # Getting the window size from the user
    window_size = 0

    #
    while window_size < 1 or window_size > 4:
        window_size = int(input("Please choose a window size for the connection (1-4):"))

        if window_size < 1 or window_size > 4:
            print("Invalid window size. Please try again.")
        elif window_size % 1 != 0:
            print("Invalid window size. Please try again.")

    print("Establishing connection with the server...")

    # Constructing and sending the SYN packet
    ether = Ether(src=clnt_mac, dst="ff:ff:ff:ff:ff:ff")
    ip    = IP(src=clnt_ip, dst=srv_ip)
    udp   = UDP(sport=clnt_port, dport=srv_port)
    rudp  = RUDP(flags=0x02)      # 0x02 = SYN

    syn_packet = ether / ip / udp / rudp
    count = 0

    while True:

        sendp(syn_packet, iface='enp0s3')
        count += 1

        # Sniffing for the SYN-ACK packet
        srv_pack = sniff(filter=f"udp and port {clnt_port}", count=1, timeout=3 ,iface='enp0s3')
        time.sleep(0.05)

        # If we received a packet, we set it to be the first packet in the list (the only packet in the list).
        if len(srv_pack) != 0:
            srv_pack = srv_pack[0]

        if len(srv_pack) == 0:

            if count < 3:
                print("No response from the server. Trying again...")
                continue

            else:
                print("Connection failed!")
                return -1

        elif RUDP in srv_pack and srv_pack[RUDP].flags == 0x03:  # 0x03 = SYN-ACK

            rudp = RUDP(flags=0x01, wndw_size=window_size)  # 0x01 = ACK
            payload = Raw(load=song_request.encode('utf-8'))
            
            response_packet = ether / ip / udp / rudp / payload

            sendp(response_packet, iface='enp0s3')

            print("Connection established successfully!")

            # Returning the server's MAC address
            return srv_pack[Ether].src

        else:
            print("Unexpected packet received. Aborting...")
            return -1


def url_to_song_name(url):
    

    # Split the URL by '/' and take the last part
    song_name = url.split('/')[-1]

    # Replace '-' with ' ' and add '.mp3' at the end
    song_name = song_name.replace('-', ' ') + '.mp3'

    # Capitalize the first letter of each word in the song name
    song_name = ' '.join(word.capitalize() for word in song_name.split())

    return song_name


# This method is responsible for receiving the file from the server.
def get_file(srv_mac, clnt_mac, srv_port, clnt_port, srv_ip, clnt_ip, requested_song):

    my_song = b''
    counta = 0
    countb = 0

    song_name = url_to_song_name(requested_song)

    # We now start a loop in which we expect to receive either a data packet or a FIN packet.
    # * The data packet informs us that the server is sending us a window of packets.
    # * The FIN packet informs us that the server is done sending the file and wants to close the connection.
    #   Therefore, we break the loop and return the file to the main method.
    while True:

        print("Waiting for a packet from the server...")
        server_packet = sniff(filter=f"udp and port {clnt_port} and host {srv_ip}", timeout=3, count=1, iface='enp0s3')

        # If we received a packet, we set it to be the first packet in the list (the only packet in the list).
        if len(server_packet) != 0:
            server_packet = server_packet[0]

        # If we didn't receive a packet, we send a NAK packet to the server.
        if len(server_packet) == 0:

            # If we tried less than 3 times, we send a NAK packet.
            if counta < 3:
                print("No packet sent from the server. Sending NAK...")
                counta += 1

                # Constructing and sending the NAK packet
                ether = Ether(src=clnt_mac, dst=srv_mac)
                ip = IP(src=clnt_ip, dst=srv_ip)
                udp = UDP(sport=clnt_port, dport=srv_port)
                rudp = RUDP(flags=0x08, wndw_size=1)  # 0x08 = NAK

                nak_packet = ether / ip / udp / rudp

                sendp(nak_packet, iface='enp0s3')

            # If it's our third try, we can assume the connection is lost, and abort the process.
            else:
                print("Connection dysfunctional. Aborting...")
                return -1

        # Otherwise, we received a packet!
        # This packet could be either:
        # 1. A data packet, containing a chunk of the file - letting us know the server is sending the rest of a window of other packets as well.
        # 2. A FIN packet, letting us know the server is done sending the file and wanting to close the connection.
        else:
            counta = 0
            temp_window = b''

            # If we received a data packet, it means we're about to receive a window of packets.
            # We add it to the temp_window variable and prepare to add the rest of the packets to it.
            if RUDP in server_packet and server_packet[RUDP].end_num != 32767:

                print(f"Received packet no. {server_packet[RUDP].seq_num} from the server.")

                temp_window += server_packet[Raw].load
                window_size = server_packet[RUDP].end_num - server_packet[RUDP].start_num + 1

                i = 1

                # We keep receiving packets until we receive the last packet in the window.
                while i < window_size:

                    server_packet = sniff(filter=f"udp and port {clnt_port} and host {srv_ip}",
                                          timeout=3, count=1, iface='enp0s3')

                    # If we received a packet, we set it to be the first packet in the list (the only packet in the list).
                    if len(server_packet) != 0:
                        server_packet = server_packet[0]

                    # If we didn't receive a packet, we send a NAK packet to the server.
                    if len(server_packet) == 0:
                        print("Server failed to send the next packet. Sending NAK and trying again...")

                        # Constructing and sending the NAK packet
                        ether = Ether(src=clnt_mac, dst=srv_mac)
                        ip = IP(src=clnt_ip, dst=srv_ip)
                        udp = UDP(sport=clnt_port, dport=srv_port)
                        rudp = RUDP(flags=0x08, wndw_size=1)  # 0x08 = NAK

                        nak_packet = ether / ip / udp / rudp

                        sendp(nak_packet, iface='enp0s3')

                        # Since we failed to receive a packet, we add 1 to each counter.
                        # We increment countb because we want to try up to 3 times to receive a window of packets correctly.
                        # But, we also increment counta because of the scenario where the server unexpectedly stops sending packets,
                        # so if such a scenario occurs, we want to try up to 3 times to re-establish the connection, not more.
                        counta += 1
                        countb += 1
                        break

                    # If we received a packet, we add it to the temporary window.
                    else:

                        print(f"Received packet no. {server_packet[RUDP].seq_num} from the server.")

                        temp_window += server_packet[Raw].load
                        i += 1

                # If we received all the packets in the window,
                # we add the data saved in temp_window to my_song, and we send an ACK packet to the server.
                # And of course, we reset the temp_window variable and the counter.
                if i == window_size:

                    countb = 0
                    my_song += temp_window

                    # Constructing and sending the ACK packet
                    ether = Ether(src=clnt_mac, dst=srv_mac)
                    ip = IP(src=clnt_ip, dst=srv_ip)
                    udp = UDP(sport=clnt_port, dport=srv_port)
                    rudp = RUDP(flags=0x01, wndw_size=1)  # 0x01 = ACK

                    ack_packet = ether / ip / udp / rudp

                    time.sleep(0.05) #####################

                    sendp(ack_packet, iface='enp0s3')

                    print("Sent ACK packet.")


                if countb == 3:
                    print("Connection dysfunctional. Aborting...")
                    return -1

            # If received a FIN packet, it means we finished receiving the file.
            elif RUDP in server_packet and server_packet[RUDP].flags == 0x04:

                # Writing the total bytes received into a new file, which will be added to our directory.
                with open(song_name, "wb") as file:
                    file.write(my_song)

                # Constructing and sending the ACK packet
                ether = Ether(src=clnt_mac, dst=srv_mac)
                ip = IP(src=clnt_ip, dst=srv_ip)
                udp = UDP(sport=clnt_port, dport=srv_port)
                rudp = RUDP(flags=0x05)  # 0x05 = FIN-ACK

                fin_packet = ether / ip / udp / rudp

                print("File received successfully!")

                attempts = 0

                # Now we enter a loop in which we expect the server to send us an ACK packet.
                # We will try up to 3 times to receive the ACK packet, and upon each unsuccessful attempt,
                # we will send the FIN-ACK packet again.
                # After 3 unsuccessful attempts, we will abort the process.
                while True:

                    time.sleep(0.05)

                    print("Sending FIN-ACK packet...")
                    sendp(fin_packet, iface='enp0s3')

                    server_ack = sniff(filter=f"udp and port {clnt_port} and host {srv_ip}", count=1, timeout= 3,iface='enp0s3')
                    time.sleep(0.05)

                    # If we received a packet, we set it to be the first packet in the list (the only packet in the list).
                    if len(server_ack) != 0:
                        server_ack = server_ack[0]

                    # If we didn't receive a packet, we send a NAK packet to the server.
                    if len(server_ack) == 0:
                        if attempts < 3:
                            print("Server failed to send ACK. Trying again...")
                            attempts += 1
                            continue
                        else:
                            print("Failed to close the connection accordingly. Aborting...")
                            return -1

                    # If we did receive a packet, we check if it's an ACK packet.
                    # If so, we close the connection successfully.
                    else:
                        if RUDP in server_ack and server_ack[RUDP].flags == 0x01:
                            print("Connection closed successfully!")
                            return 0
                        else:
                            print("Unexpected packet received. Aborting...")
                            return -1

                print("Failed to close the connection accordingly. Aborting...")
                return -1


# This method is responsible for starting the UDP server, and calling the other methods.
def rudp_client(srv_port, clnt_port, srv_ip, clnt_ip, clnt_mac, song_requested):

    bind_layers(UDP, RUDP)

    # Establish the connection
    server_mac = initial_connection(clnt_mac, srv_port, clnt_port, srv_ip, clnt_ip, song_requested)

    # If the connection was not established, exit the program
    if server_mac is None or server_mac == -1:
        print("Connection could not be established.")
        exit(1)

    # If the connection was established, get the file from the server
    got = get_file(server_mac, clnt_mac, srv_port, clnt_port, srv_ip, client_ip, song_requested)


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
HOST = domain_ip   

# Using the request suggestion function, we get a redirect location for a song.
song_location = request_suggestion(HOST, server_port)

# Now, we parse the ip address from the location:

parsed_url = urlparse(song_location)
server_address = parsed_url.hostname

print(server_address)
server_port = 5001
client_port = 5000

# Now, we can start the RUDP connection with the server:

rudp_client(server_port, client_port, server_address, client_ip, client_mac, song_location)

# We can now play the song we got from the server:

print("The song is now in your project's directory.")
print("Thank you for using our service!")

exit(0)