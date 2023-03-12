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
{'name': 'song 1', 'language': 'A', 'genre': '1', 'url': 'http://10.0.0.100/bad-habits'},
{'name': 'song 2', 'language': 'A', 'genre': '1', 'url': 'http://10.0.0.100/shivers'},
{'name': 'song 3', 'language': 'A', 'genre': '1', 'url': 'http://10.0.0.100/one-more-night'},
{'name': 'song 4', 'language': 'A', 'genre': '1', 'url': 'http://10.0.0.100/see-you-again'},
# pop spanish songs
{'name': 'song 5', 'language': 'B', 'genre': '1', 'url': 'http://10.0.0.100/te-pienso'},
{'name': 'song 6', 'language': 'B', 'genre': '1', 'url': 'http://10.0.0.100/me-porto-bonito'},
{'name': 'song 7', 'language': 'B', 'genre': '1', 'url': 'http://10.0.0.100/ilusion'},
# pop Italian songs 
{'name': 'song 8', 'language': 'C', 'genre': '1', 'url': 'http://10.0.0.100/italian-pop-1'},
{'name': 'song 9', 'language': 'C', 'genre': '1', 'url': 'http://10.0.0.100/italian-pop-2'},
{'name': 'song 10', 'language': 'C', 'genre': '1', 'url': 'http://10.0.0.100/italian-pop-3'},
# country songs english
{'name': 'song 11', 'language': 'A', 'genre': '3', 'url': 'http://10.0.0.100/friends-in-low-places'},
{'name': 'song 12', 'language': 'A', 'genre': '3', 'url': 'http://10.0.0.100/i-walk-the-line'},
{'name': 'song 13', 'language': 'A', 'genre': '3', 'url': 'http://10.0.0.100/amazed'},
# country spanish songs
{'name': 'song 14', 'language': 'B', 'genre': '3', 'url': 'http://10.0.0.100/country-spanish-1'},
{'name': 'song 15', 'language': 'B', 'genre': '3', 'url': 'http://10.0.0.100/country-spanish-2'},
{'name': 'song 16', 'language': 'B', 'genre': '3', 'url': 'http://10.0.0.100/country-spanish-3'},
# country French songs
{'name': 'song 17', 'language': 'D', 'genre': '3', 'url': 'http://10.0.0.100/french-country-1'},
{'name': 'song 18', 'language': 'D', 'genre': '3', 'url': 'http://10.0.0.100/french-country-2'},


# classic spanish songs

# classic Italian songs

# Country english songs 

# Contry Spanish songs
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
        response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".encode()
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

    except(socket.error, socket.gaierror, OSError, ValueError) as e:
        print(f'Error occurred: {e}')

if __name__ == '__main__':
    start_the_server()
