import socket
import threading

#######################################################
#                                                     #
#   Simple PROXY                                      #
#                                                     #
#######################################################

TIMEOUT = 120  # seconds
PORT_CLIENT = 4433
PORT_SERVER = 443
HOSTNAME = 'twitter.com'


def forward(from_socket, to_socket):
    while True:
        try:
            data = from_socket.recv(4096)
        except TimeoutError:
            return
        to_socket.send(data)


def handle(client_socket):
    # open socket to server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(TIMEOUT)
    server_socket.connect((HOSTNAME, PORT_SERVER))
    threading.Thread(target=forward, args=(client_socket, server_socket)).start()
    threading.Thread(target=forward, args=(server_socket, client_socket)).start()


# opening server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", PORT_CLIENT))
server.listen()

while True:  # listen for incoming connections
    client_socket, address = server.accept()
    client_socket.settimeout(TIMEOUT)
    print("request from the ip", address[0])
    # spawn a new thread that run the function handle()
    threading.Thread(target=handle, args=(client_socket,)).start()
