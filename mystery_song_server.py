from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import socket
import random

HOST = 'localhost'
SERVER_PORT = 30197


# This is our songs pool. It holds all the domains and their associated IP addresses.
    # We initialize it with the domain of the app we created.

song_pool = [
# pop english songs
{'name': 'song 1', 'language': 'A', 'genre': '1', 'url': 'http://10.0.0.100/ed-sheeran-perfect'},
{'name': 'song 2', 'language': 'A', 'genre': '1', 'url': 'http://10.0.0.100/lady-gaga-poker-face'},
# hip hop english songs
{'name': 'song 3', 'language': 'A', 'genre': '2', 'url': 'http://10.0.0.100/kendrick-lamar-humble'},
{'name': 'song 4', 'language': 'A', 'genre': '2', 'url': 'http://10.0.0.100/eminem-the-real-slim-shady'},
# rock english songs 
{'name': 'song 5', 'language': 'A', 'genre': '3', 'url': 'http://10.0.0.100/beatles-let-it-be'},
{'name': 'song 6', 'language': 'A', 'genre': '3', 'url': 'http://10.0.0.100/led-zeppelin-immigrant-song'},
# pop hebrew songs
{'name': 'song 7', 'language': 'B', 'genre': '1', 'url': 'http://10.0.0.100/noa-kirel-kila'},
{'name': 'song 8', 'language': 'B', 'genre': '1', 'url': 'http://10.0.0.100/mergui-lo-lihiyot-levad'},
# hip hop hebrew songs
{'name': 'song 9', 'language': 'B', 'genre': '2', 'url': 'http://10.0.0.100/tuna-sahara'},
{'name': 'song 10', 'language': 'B', 'genre': '2', 'url': 'http://10.0.0.100/shachar-seol-bam-bam-bam'},
# rock hebrew songs 
{'name': 'song 11', 'language': 'B', 'genre': '3', 'url': 'http://10.0.0.100/kaveret-hora'},
{'name': 'song 12', 'language': 'B', 'genre': '3', 'url': 'http://10.0.0.100/dudu-tasa-goral'},
# french pop songs
{'name': 'song 13', 'language': 'C', 'genre': '1', 'url': 'http://10.0.0.100/stromae-alors-on-danse'},
# french hip hop songs
{'name': 'song 14', 'language': 'C', 'genre': '2', 'url': 'http://10.0.0.100/soprano-victory'},
# italian rock songs
{'name': 'song 15', 'language': 'D', 'genre': '3', 'url': 'http://10.0.0.100/maneskin-zitti-e-buoni'}

]

def handle_client_song_request(client_socket):
    # receive request from client
    request = client_socket.recv(1024).decode('utf-8')
    
    # Find the name of the song that we want to download
    song_requested = request.split()[1][1:]

    # Split to genre and language
    song_genre_langauage = song_requested.split('-')

    # filter the list by genre and language
    filtered_songs = [song for song in song_pool if song['genre'] == song_genre_langauage[0]
                       and song['language'] == song_genre_langauage[1]]
    
    # choose a random song as requested 
    if filtered_songs:
        song = random.choice(filtered_songs)
        song_url = song['url']

        # create response with 301 redirect - figure out how to add the song name to path
        response = b"HTTP/1.1 301 Moved Permanently\r\nLocation: {songurl}\r\n\r\n" 
        formatted_response = f"{response.decode('utf-8').format(songurl=song_url)}".encode('utf-8')
        client_socket.sendall(formatted_response)


    else:
        print("No songs match the given criteria.")
        response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        client_socket.sendall(response)


    # close client connection
    client_socket.close()

def start_the_server():

    try:
        # create TCP socket
        song_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # bind socket
        song_server_socket.bind((HOST, SERVER_PORT))

        # listen for connections
        song_server_socket.listen()

        print(f"Server is listening on port {SERVER_PORT}...")

        while True:
            # accept client connection
            client_socket, address = song_server_socket.accept()

            # handle client request in a new thread
            handle_client_song_request(client_socket)
            
            continue_listening = ''

            while (continue_listening != 'y' and continue_listening != 'n'):
                
                # ask server if to continue listening
                continue_listening = input("Do you want to continue listening? (y/n): ")
                
                if continue_listening == 'n':
                    song_server_socket.close()
                    
                elif continue_listening == 'y':
                    continue
                   
                else:
                    print("Invalid input. Please enter 'y' or 'n'.")

            if continue_listening == 'n':
                break


    except(socket.error, socket.gaierror, OSError, ValueError) as e:
        print(f'Error occurred: {e}')

if __name__ == '__main__':
    start_the_server()
