from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from RUDP import RUDP

# These are global variables, in which we need all methods to have access to.
# One is a window size - an amount of packets sent in a row, before waiting for an ACK packet.
# The other is a threshold - a variable that stops the acceleration of the window size's inflation.
window_size = 1
threshold = 16


# This method is responsible for making the initial connection between the client and the server.
# It does so by sending a SYN packet from the client, and then receiving a SYN-ACK packet from the server.
# The client then send an ACK packet back to the server, and the connection is established.
# Afterwards, the client gets ready to receive packets from the client.
def initial_connection(srv_mac, srv_port, srv_ip):

    global window_size

    print("")
    print("Waiting for connection...")

    clnt_pack = sniff(filter=f"udp and port {srv_port}", count=1,iface='enp0s3')[0]
    time.sleep(0.05)

    # If we received a SYN packet from a client, we send them a SYN-ACK packet back.
    if clnt_pack and RUDP in clnt_pack and clnt_pack[RUDP].flags == 0x02:

        clnt_mac  = clnt_pack[Ether].src
        clnt_port = clnt_pack[UDP].sport
        clnt_ip   = clnt_pack[IP].src

        print(f"Establishing connection with a client, ip: {clnt_ip}")

        ether = Ether(src=srv_mac, dst=clnt_mac)
        ip    = IP(src=srv_ip, dst=clnt_ip)
        udp   = UDP(sport=srv_port, dport=clnt_port)
        rudp  = RUDP(flags=0x03)  # 0x03 = SYN + ACK
        response_packet = ether / ip / udp / rudp

        count = 0

        # Sending the SYN-ACK packet 3 times to ensure it gets to the client.
        # * If the client doesn't respond with an ACK packet, we try again.
        # * If the client doesn't respond after 3 tries, we abort the connection.
        # * If the client responds with an ACK packet, we establish the connection.
        while True:

            print("Sending SYN-ACK packet...")

            sendp(response_packet, iface='enp0s3')
            count += 1

            # We wait for the client to send us an ACK packet.
            clnt_pack = sniff(filter=f"udp and port {srv_port} and host {clnt_ip} ", timeout=3, count=1, iface='enp0s3')[0]

            # If we received a packet, we set it to be the first packet in the list (the only packet in the list).
            if len(clnt_pack) != 0:
                clnt_pack = clnt_pack[0]

            time.sleep(0.05)

            print("")

            # If we didn't receive a packet, we try again.
            if len(clnt_pack) == 0:

                # If we haven't tried 3 times yet, we try again.
                if count < 3:
                    print("No response from client, trying again...")
                    continue

                # If we didn't receive a packet after 3 tries, we abort the connection.
                else:
                    print("Connection failed.")
                    return None, None, None

            else:

                if RUDP in clnt_pack and clnt_pack[RUDP].flags == 0x01:

                    window_size = clnt_pack[RUDP].wndw_size
                    print("Connection established successfully!")
                    return clnt_mac, clnt_port, clnt_ip

                else:
                    print("Unexpected packet received, aborting...")
                    print("")
                    return None, None, None

    else:
        print("Unexpected packet received, aborting...")
        print("")
        return None, None, None


# This method is responsible for ending the connection between the client and the server.
# It will be used after we have sent all the packets to the client properly.
# It does so by sending a FIN packet from the client, and then receiving a FIN-ACK packet from the server.
# The client then send an ACK packet back to the server, and the connection is terminated safely.
def end_connection(clnt_mac, srv_mac, clnt_port, srv_port, clnt_ip, srv_ip):

    ether = Ether(src=srv_mac, dst=clnt_mac)
    ip    = IP(src=srv_ip, dst=clnt_ip)
    udp   = UDP(sport=srv_port, dport=clnt_port)
    rudp  = RUDP(flags=0x04)  # 0x04 = FIN
    fin_packet = ether / ip / udp / rudp

    count = 0

    # Sending the FIN packet 3 times to ensure it gets to the client.
    # * If the client doesn't respond with a FIN-ACK packet, we try again.
    # * If the client doesn't respond after 3 tries, we abort the connection.
    # * If the client responds with a FIN-ACK packet, we send a final ACK packet to the client, and close the connection.
    while True:

        print("Sending FIN packet...")

        sendp(fin_packet, iface='enp0s3')
        count += 1

        client_pack = sniff(filter=f"udp and port {srv_port} and host {clnt_ip} ", timeout=3, count=1, iface='enp0s3')
        time.sleep(0.05)

        # If we received a packet, we set it to be the first packet in the list (the only packet in the list).
        if len(client_pack) != 0:
            client_pack = client_pack[0]

        # If we didn't receive a packet, we try again 3 times.
        # If we didn't receive a packet after 3 tries, we abort the connection.
        if len(client_pack) == 0:

            if count < 3:
                print("No response from client, trying again...")
                continue

            else:
                print("Safe termination failed. Aborting...")
                print("")
                return -1

        # If we received a packet, we check if it's a FIN-ACK packet.
        else:

            # If we received a FIN-ACK packet, we send a final ACK packet to the client, and close the connection.
            if RUDP in client_pack and client_pack[RUDP].flags == 0x05:

                # If we received a FIN-ACK packet from the client, all we have to do is send them a final ACK packet back.
                # Afterwards, we can close the connection safely.
                print("Received FIN-ACK packet from client")
                print("sending final ACK packet and closing the connection...")

                rudp = RUDP(flags=0x01)  # 0x01 = ACK

                ack_packet = ether / ip / udp / rudp

                sendp(ack_packet, iface='enp0s3')

                return 0

            # If we received a packet that wasn't a FIN-ACK packet, we abort the connection.
            else:
                print("Unexpected packet received.")
                print("Safe termination failed. Aborting...")
                print("")
                return -1



# This method is responsible for dividing the file into chunks so that their size would be suitable to be added to packets.
def div_file(name):
    with open(name, "rb") as file:
        song = file.read()

    # Calculate the midpoint of the file
    file_size = len(song)
    chunk_size = 1400

    # Split the file into two parts
    file_chunks = []
    start = 0
    end = chunk_size

    while (start + chunk_size) <= (file_size - 1):
        file_chunks.append(song[start:end])
        start += chunk_size
        end   += chunk_size

    end = file_size - 1
    file_chunks.append(song[start:end])

    return file_chunks


def send_file(clnt_mac, srv_mac, clnt_port, srv_port, clnt_ip, srv_ip, file_chunks):

    global window_size           # This is the maximum size of the window.
    global threshold             # This is the threshold of the window.

    # We initialize the start and end indices of the window,
    # and a counter that will help us decide if to abort the connection.
    start = 0
    end = window_size - 1
    count = 0

    print(f"Number of packets to send: {len(file_chunks)}")

    # We now start a loop that will send the packets to the client.
    # We try sending a window of packets 3 times.
    # * If the client doesn't respond, we try again with a smaller window size.
    # * If the client doesn't respond after 3 tries, we abort the connection.
    # * If the client responds, we send the next window of packets.
    # * If the client responds with a duplicate ACK, we increase the window size.
    while True:

        # If we sent the window 3 times and didn't get a response, we abort the connection.
        if count == 3:
            print("Connection is dysfunctional, aborting...")
            print("")
            return -1

        # If the start index is greater than the length of the file chunks, we have sent all the packets.
        # We can now exit the loop.
        if start > len(file_chunks):

            print ("File sent successfully!")
            break

        i = 0

        for file_chunk in file_chunks[start:end+1]:

            # Constructing and sending the RUDP packet containing the chunk of the file to the server
            eth = Ether(src=srv_mac, dst=clnt_mac)
            ip = IP(src=srv_ip, dst=clnt_ip)
            udp = UDP(sport=srv_port, dport=clnt_port)
            payload = Raw(load=file_chunk)
            rudp = RUDP(payl_size=len(payload.load),seq_num=start+i, start_num=start, end_num=end) # we set the end_num to the window's last packet.

            chunk_packet = eth / ip / udp / rudp / payload

            print(f"Sending packet no. {start + i} to client.")

            sendp(chunk_packet, iface='enp0s3')

            if start + i != end:
                time.sleep(0.02) ################

            i += 1

        count += 1

        print("Finished sending window, waiting for ACK...")
        # We wait for the client to send us an ACK packet for the window we sent.
        clnt_pack = sniff(filter=f"udp and port {srv_port} and host {clnt_ip} ", timeout=10, count=1, iface='enp0s3')
        time.sleep(0.02)    ################

        # If we received a packet, we set it to be the first packet in the list (the only packet in the list).
        if len(clnt_pack) != 0:
            clnt_pack = clnt_pack[0]

        # If the client doesn't respond, we try again with a smaller window size.
        if len(clnt_pack) == 0:
            threshold = window_size // 2
            window_size = threshold
            print("No response from client, trying again...")

        else:
            if RUDP in clnt_pack and clnt_pack[RUDP].flags == 0x01:

                print("Received ACK from client.")

                # If we got an ack on the last window of packets, we can exit the loop.
                if end == len(file_chunks) - 1:
                    print("File sent successfully!")

                    # We reset the window size and threshold to their initial values.
                    threshold = 16
                    window_size = 1

                    break

                # If the window size * 2 would be bigger than the threshold, we increase the window size by 1.
                # Otherwise, we can safely double the window size.
                if window_size * 2 > threshold:
                    window_size += 1
                else:
                    window_size *= 2

                # We move the window to the next set of packets, with the new window size.
                start = end + 1
                end = end + window_size
                end = min(end, len(file_chunks) - 1 )

                count = 0 # We reset the counter.

            # If the client sends us a nak, we decrease the threshold and window size by half,
            # and we try again with a smaller window.
            else:
                threshold = window_size // 2
                window_size = threshold

                # We update the end index to match the new window size.
                end = start + window_size - 1
                print("Client failed to get the packets, trying again...")

    return 0


def rudp_server():

    bind_layers(UDP, RUDP)

    server_port = 5001
    server_ip = '10.0.0.21'
    server_mac = str(get_if_hwaddr('enp0s3'))

    while True:

        client_mac, client_port, client_ip = initial_connection(server_mac, server_port, server_ip)

        if client_mac and client_port and client_ip:

            file_chunks = div_file("/home/barakfinkel/Desktop/Tada-sound.mp3")
            send_file(client_mac, server_mac, client_port, server_port, client_ip, server_ip, file_chunks)

            end_connection(client_mac, server_mac, client_port, server_port, client_ip, server_ip)


## MAIN ##

# Start the UDP client
rudp_server()