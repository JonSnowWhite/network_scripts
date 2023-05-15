import socket
import threading

#######################################################
#                                                     #
#   HTTP CONNECT PROXY                                #
#                                                     #
#######################################################

TIMEOUT = 120  # seconds
PORT_CLIENT = 4433
RECORD_FRAG = False
FRAG_SIZE = 20

TLS_1_0_HEADER = b'\x16\x03\x01'
TLS_1_1_HEADER = b'\x16\x03\x02'
TLS_1_2_HEADER = b'\x16\x03\x03'


def forward(from_socket, to_socket, record_frag=False):
    buffer = b''
    need_more = True
    while True:
        if need_more:
            try:
                buffer += from_socket.recv(4096)
            except TimeoutError:
                return
        if not record_frag:
            to_socket.send(buffer)
            buffer = b''
            need_more = True
            continue

        # only record fragment tls messages
        is_tls = buffer[:3] == TLS_1_0_HEADER or buffer[:3] == TLS_1_1_HEADER or buffer[:3] == TLS_1_2_HEADER
        if not is_tls:
            to_socket.send(buffer)
            buffer = b''
            need_more = True
            continue


        # need to parse more data to get record length etc.
        if len(buffer) < 5:
            need_more = True
            continue

        # get record length
        record_length = int.from_bytes(buffer[3:5], byteorder='big')
        # check if we have the full record
        if len(buffer) < record_length + 5:
            need_more = True
            continue

        # split buffer into fragments
        base_header = buffer[:3]
        rest_buffer = buffer[5 + record_length:]
        buffer = buffer[5:5 + record_length]
        fragments = [buffer[i:i + FRAG_SIZE] for i in range(0, record_length, FRAG_SIZE)]
        buffer = rest_buffer

        for fragment in fragments:
            # construct header
            header = base_header + int.to_bytes(len(fragment), byteorder='big', length=2)
            to_socket.send(header + fragment)
        need_more = False


def handle(client_socket):
    # check if first message is a CONNECT method
    try:
        data = client_socket.recv(4096)
        first_line = data.decode().split('\n')[0]
        url = first_line.split(' ')[1]

        # Extract the host and port from the URL
        host, port = url.split(':')
    except:
        # not a connect method
        return

    # answer with 200 OK
    client_socket.send(b'HTTP/1.1 200 OK\n\n')

    # open socket to server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(TIMEOUT)
    server_socket.connect((host, int(port)))
    threading.Thread(target=forward, args=(client_socket, server_socket, RECORD_FRAG)).start()
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
    threading.Thread(target=handle, args=(client_socket, )).start()
