import logging
import socket
import sys
import threading
from time import time

import dns.query
import dns.message
import dns.rdatatype
from enum import Enum
import argparse

#######################################################
#                                                     #
#   HTTP CONNECT PROXY                                #
#                                                     #
#######################################################

# only fragment handshake messages
TLS_1_0_HEADER = b'\x16\x03\x01'
TLS_1_1_HEADER = b'\x16\x03\x02'
TLS_1_2_HEADER = b'\x16\x03\x03'

HTTP_200_RESPONSE = b'HTTP/1.1 200 OK\n\n'


def is_valid_ipv4_address(ip_address: str) -> bool:
    """
    Returns whether the given string is a valid ipv4 address.
    :param ip_address: String to check for ipv4 validity
    :return: Whether the given string is a valid ip address
    """
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False


class ProxyMode(Enum):
    """
    Modes the proxy can operate in
    """
    ALL = 0,
    HTTP = 1
    HTTPS = 2,
    SNI = 3

    # TODO: SOCKSv4 = 4
    # TODO: SOCKSv5 = 5

    def __str__(self):
        return self.name


class ParserException(Exception):
    """For exceptions during the parsing process"""

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)


class WrappedSocket:
    """
    Wraps a socket with useful utility functions.
    """

    def __init__(self, timeout: int, _socket: socket.socket):
        self.timeout = timeout
        self.buffer = b''
        self.socket = _socket
        self.socket.settimeout(timeout)

    def read(self, size: int) -> bytes:
        """
        Reads specified amount of data from socket. Blocks until amount of data received or timeout.
        :param size: Data to read.
        :return: Read data
        """
        while len(self.buffer) < size:
            self.buffer += self.socket.recv(4096)
        _res = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return _res

    def peek(self, size: int) -> bytes:
        """
        Similar to read, but keeps data in buffer.
        """
        while len(self.buffer) < size:
            self.buffer += self.socket.recv(4096)
        return self.buffer[:size]

    def recv(self, size: int, *args, **kwargs) -> bytes:
        """
        Works similar to recv of the wrapped socket. Prepends any bytes still buffered.
        :param size: Size of the buffer to read into.
        :return: Bytes read from the socket
        """
        if len(self.buffer) > 0:
            _res = self.buffer
            self.buffer = b''
        else:
            _res = self.socket.recv(size, *args, **kwargs)
        return _res

    def send(self, *args, **kwargs) -> int:
        """
        Wraps send() of the wrapped socket.
        :return: Return value of the wrapped socket's send method
        """
        return self.socket.send(*args, **kwargs)

    def close(self):
        self.socket.close()

    def inject(self, content: bytes):
        """
        Injects bytes to the front of the buffer. Can be used to write back read data.
        :param content: the bytes to prepend
        :return: None
        """
        self.buffer = content + self.buffer

    def read_tls_record(self) -> bytes:
        """
        Reads the content of the next tls record from the wire with headers. Throws exception if no record is received.
        :return: The contents of the TLS record
        """
        # read record header
        data = self.read(5)

        # check if first 3 bytes are a tls header
        if data[:3] != TLS_1_0_HEADER and data[:3] != TLS_1_1_HEADER and data[:3] != TLS_1_2_HEADER:
            raise ParserException("Not a TLS connection")

        # read record length
        record_length = int.from_bytes(data[3:5], byteorder='big')
        return data + self.read(record_length)

    def read_tls_message(self, peek=False) -> bytes:
        """
        Reads the content of the next tls message from the socket.
        :param: whether to peek the tls message.
        :return: The content of the TLS message
        """
        message = b''
        buffer = b''
        # headers
        len_to_read = 4
        # prevent infinite sockets
        timestamp = time()
        # parse records until message complete
        while len(message) < len_to_read and int(time() - timestamp) < self.timeout:
            record = self.read_tls_record()
            buffer += record
            message += record[5:]
            if len(message) >= 4:
                # can parse message length
                len_to_read = int.from_bytes(message[1:4], byteorder='big')
        if peek:
            # re-inject all read records
            self.inject(buffer)
        return message


class Proxy:
    """
    Proxy server
    """

    def __init__(self, timeout: int = 120, port: int = 4433, record_frag: bool = False, frag_size: int = 20,
                 dot: bool = False,
                 dot_ip: str = "8.8.4.4", proxy_mode: ProxyMode = ProxyMode.ALL, forward_proxy_address: str = None,
                 forward_proxy_port: int = None, forward_proxy_mode: ProxyMode = ProxyMode.SNI,
                 forward_proxy_resolve_address: bool = False):
        # timeout for socket reads and message reception
        self.timeout = timeout
        # own port
        self.port = port
        # record fragmentation settings
        self.record_frag = record_frag
        self.frag_size = frag_size
        # whether to use dot for domain resolution
        self.dot = dot
        self.dot_ip = dot_ip
        # own proxy mode
        self.proxy_mode = proxy_mode
        # settings for another proxy to contact further down the line
        self.forward_proxy_address = forward_proxy_address
        self.forward_proxy_port = forward_proxy_port
        self.forward_proxy_mode = forward_proxy_mode
        self.forward_proxy_resolve_address = forward_proxy_resolve_address
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def resolve_domain(self, domain: str) -> str | None:
        """
        Resolves the given domain to an ip address.
        :param domain: domain name to resolve
        :return: One ip address for the domain or None
        """
        if not self.dot:
            return socket.gethostbyname(domain)
        else:
            # TODO: doh/doq
            domain = dns.name.from_text(domain)
            if not domain.is_absolute():
                domain = domain.concatenate(dns.name.root)

            query = dns.message.make_query(domain, dns.rdatatype.A)
            query.flags |= dns.flags.AD
            query.find_rrset(query.additional, dns.name.root, 65535,
                             dns.rdatatype.OPT, create=True, force_unique=True)
            response = dns.query.tls(query, self.dot_ip)

            if response.rcode() != dns.rcode.NOERROR:
                return None

            # filter ipv4 answer
            ips = []
            for record in response.answer:
                if record.rdtype == dns.rdatatype.A:
                    for item in record.items:
                        ips.append(str(item.address))
            if len(ips) > 0:
                return ips[0]
            else:
                # read CNAME hostnames from answer
                for record in response.answer:
                    if record.rdtype == dns.rdatatype.CNAME:
                        for item in record.items:
                            return self.resolve_domain(str(item.target))
                return None

    def forward(self, from_socket: WrappedSocket, to_socket: WrappedSocket, record_frag=False):
        """
        Forwards data between two sockets with optional record fragmentation. Falls back to forwarding if no TLS records
        can be parsed from the connection anymore.
        :param to_socket: Socket to receive data from.
        :param from_socket: Socket to forward data to.
        :param record_frag: Whether to fragment handshake records
        :return: None
        """
        try:
            while True:
                if not record_frag:
                    to_socket.send(from_socket.recv(4096))
                else:
                    try:
                        record_header = from_socket.peek(5)
                    except:
                        logging.debug("Could not read record_header bytes")
                        record_frag = False
                        continue
                    base_header = record_header[:3]
                    record_len = int.from_bytes(record_header[3:], byteorder='big')
                    is_tls = base_header == TLS_1_0_HEADER or base_header == TLS_1_1_HEADER \
                             or base_header == TLS_1_2_HEADER
                    if not is_tls:
                        logging.debug(f"Not a TLS handshake record header: {record_header}")
                        # did not receive tls record
                        record_frag = False
                        continue
                    try:
                        record = from_socket.read(5 + record_len)[5:]
                    except:
                        logging.debug(f"Could not read {record_len} record bytes")
                        record_frag = False
                        continue
                    fragments = [record[i:i + self.frag_size] for i in range(0, record_len, self.frag_size)]
                    fragmented_message = b''
                    for fragment in fragments:
                        # construct header
                        fragmented_message += base_header + int.to_bytes(len(fragment), byteorder='big', length=2)
                        fragmented_message += fragment
                    to_socket.send(fragmented_message)
        except BrokenPipeError:
            logging.info(f"Forwarding from {from_socket.socket.getpeername()} to {to_socket.socket.getpeername()} "
                         f"broken.")

    @staticmethod
    def read_http_get(client_socket: WrappedSocket) -> str:
        """
        Reads the first line of a http get request to parse the domain from it.
        :param client_socket: Socket to read from.
        :return: host in the get request
        """
        found = False
        data = b''
        i = 12  # GET http://
        # increasingly peek until we find the linebreak
        while not found and i < 200:
            data = client_socket.peek(i)
            if data[i-1] == b'\n':
                found = True
            else:
                i += 1
        host = data[11:].split(b'/')[0].decode('ASCII')  # cut GET http:// and parse until first slash

        return host

    @staticmethod
    def read_http_connect(client_socket: WrappedSocket) -> (str, int):
        """
        Reads the first line of a http connect request.
        :param client_socket: Socket to read from.
        :return: host and port from the http connect request.
        """
        # check if first message is a CONNECT method
        try:
            data = client_socket.recv(4096)
            first_line = data.decode().split('\n')[0]
            url = first_line.split(' ')[1]

            # Extract the host and port from the URL
            host, port = url.split(':')

            return host, int(port)
        except Exception as e:
            # not a connect method
            raise ParserException(f"Could not read CONNECT method with exception {e}")

    @staticmethod
    def read_sni(client_socket: WrappedSocket) -> str:
        """
        Attempts to read the host from the SNI extension. If the client does not send a SNI extension, None is returned.
        :param client_socket: Socket to read from
        :return: host of the sni extension
        """

        try:
            tls_message = client_socket.read_tls_message(peek=True)
        except ParserException as e:
            raise e
        except Exception as e:
            raise ParserException(e)

        # check if record is a client hello
        if tls_message[0] != 0x01:
            raise ParserException("Not a client hello")

        # skip everything until SNI extension
        p = 38
        # session_id
        p += 1 + int.from_bytes(tls_message[p:p + 1], byteorder='big')
        # cipher suites
        p += 2 + int.from_bytes(tls_message[p:p + 2], byteorder='big')
        # compression methods
        p += 1 + int.from_bytes(tls_message[p:p + 1], byteorder='big')

        if p >= len(tls_message):
            raise ParserException("No extensions present")

        # extensions
        p += 2

        while p < len(tls_message):
            ext_type = int.from_bytes(tls_message[p:p + 2], byteorder='big')
            p += 2
            ext_length = int.from_bytes(tls_message[p:p + 2], byteorder='big')
            p += 2

            if ext_type != 0:
                # skip over not sni
                p += ext_length
            else:
                # sni
                list_len = int.from_bytes(tls_message[p:p + 2], byteorder='big')
                p += 2
                _list_len = p + list_len
                while p < _list_len:
                    name_type = int.from_bytes(tls_message[p:p + 1], byteorder='big')
                    p += 1
                    name_len = int.from_bytes(tls_message[p:p + 2], byteorder='big')
                    p += 2
                    if name_type != 0:
                        # unknown name type, skip
                        p += name_len
                    else:
                        # hostname
                        hostname = tls_message[p:p + name_len]
                        return hostname.decode("ASCII")
        raise ParserException("No SNI present")

    def get_destination_address(self, ssocket: WrappedSocket) -> (str, int, bool):
        """
        Reads a proxy destination address and returns the host and port of the destination.
        :return: Host and port of the destination server.
        """
        proxy_mode = self.proxy_mode
        # dynamically determine proxy mode
        if proxy_mode == ProxyMode.ALL:
            header = ssocket.peek(16)
            if header.startswith(b'GET ') or header.startswith(b'POST '):
                logging.info('HTTP Proxy Request')
                proxy_mode = ProxyMode.HTTP
            elif header.startswith(b'CONNECT'):
                logging.info('HTTPS Proxy Request')
                proxy_mode = ProxyMode.HTTPS
            elif header.startswith(TLS_1_0_HEADER) or header.startswith(TLS_1_1_HEADER) \
                    or header.startswith(TLS_1_2_HEADER):
                logging.info('SNI Proxy Request')
                proxy_mode = ProxyMode.SNI
            else:
                raise ParserException(f"Could not determine message type of message {header}")

        if proxy_mode == ProxyMode.HTTP:
            host, port, needs_proxy_message = self.read_http_get(ssocket), 80, False
            # answer with 200 OK
            # ssocket.send(HTTP_200_RESPONSE)
            logging.debug(f"Read host {host} and port {port} from HTTP GET")
        elif proxy_mode == ProxyMode.HTTPS:
            host, port = self.read_http_connect(ssocket)
            needs_proxy_message = True
            # answer with 200 OK
            ssocket.send(HTTP_200_RESPONSE)
            logging.debug(f"Read host {host} and port {port} from HTTP connect")
        elif proxy_mode == ProxyMode.SNI:
            host, port, needs_proxy_message = self.read_sni(ssocket), 443, True
            logging.debug(f"Read host {host} and port {port} from SNI")
        else:
            raise ParserException("Unknown proxy type")
        return host, port, needs_proxy_message

    def handle(self, client_socket: WrappedSocket):
        """
        Handles the connection to a single client.
        :param client_socket: The socket of the client connection.
        :return: None
        """
        logging.debug("handling request")
        # determine destination address
        try:
            host, port, needs_proxy_message = self.get_destination_address(client_socket)
        except ParserException as e:
            logging.warning(f"Could not parse initial proxy message with {e}. Stopping!")
            return

        # resolve domain if forward host wants it, or we do not have a forward host
        if not is_valid_ipv4_address(host) and \
                (self.forward_proxy_resolve_address or self.forward_proxy_address is None):
            _host = host
            host = self.resolve_domain(host)
            logging.debug(f"Resolved {host} from {_host}")

        # set correct target
        if self.forward_proxy_address is None:
            target_host = host
            target_port = port
        else:
            target_host = self.forward_proxy_address
            target_port = self.forward_proxy_port
            logging.debug(f"Using forward proxy. Changing {host}->{target_host} and {port}->{target_port}")

        # open socket to server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((target_host, target_port))
        server_socket = WrappedSocket(self.timeout, server_socket)
        logging.debug(f"Connected to {target_host}:{target_port}")

        # send proxy messages if necessary
        # TODO: also support proxy authentication?
        if self.forward_proxy_address is not None and self.forward_proxy_mode == ProxyMode.HTTPS \
                and needs_proxy_message:
            server_socket.send(f'CONNECT {host}:{port} HTTP/1.1\nHost: {host}:{port}\n\n'
                               .encode('ASCII'))
            logging.debug("Send HTTP CONNECT to forward proxy")
            # receive HTTP 200 OK
            answer = server_socket.recv(4096)
            if not answer.startswith(HTTP_200_RESPONSE):
                logging.debug("Forward proxy rejected the connection")

        # start proxying
        threading.Thread(target=self.forward, args=(client_socket, server_socket, self.record_frag)).start()
        threading.Thread(target=self.forward, args=(server_socket, client_socket)).start()

    def start(self):
        """
        Starts the proxy. After calling the proxy is listening for connections.
        :return:
        """
        # opening server socket
        self.server.bind(("0.0.0.0", self.port))
        self.server.listen()
        print(f"### Started {self.proxy_mode} proxy on {self.port} ###")
        while True:  # listen for incoming connections
            client_socket, address = self.server.accept()
            client_socket = WrappedSocket(self.timeout, client_socket)
            logging.debug(f"request from the ip {address[0]}")
            # spawn a new thread that run the function handle()
            threading.Thread(target=self.handle, args=(client_socket,)).start()


def initialize_parser():
    """
    Registers all arguments for command line parsing.
    :return:
    """
    parser = argparse.ArgumentParser(description='Optional app description')

    parser.add_argument_group('Fast settings')
    parser.add_argument('--setting', type=int,
                        default=-1,
                        help='Fast setting for proxy setup.')

    # Standard arguments
    parser.add_argument_group('Standard arguments')

    parser.add_argument('--debug', type=bool,
                        default=False,
                        action=argparse.BooleanOptionalAction,
                        help="Turns on debugging")

    parser.add_argument('--proxy_mode', type=ProxyMode,
                        default=ProxyMode.ALL,
                        help='Which type of proxy to run')

    parser.add_argument('--timeout', type=int,
                        default=120,
                        help='Connection timeout in seconds')

    parser.add_argument('--port', type=int,
                        default=4433,
                        help='Port the proxy server runs on')

    parser.add_argument('--record_frag', type=bool,
                        default=False,
                        action=argparse.BooleanOptionalAction,
                        help='Whether to use record fragmentation to forward tls messages')

    parser.add_argument('--frag_size', type=int,
                        default=20,
                        help='Bytes in each record fragment')

    parser.add_argument('--dot', type=bool,
                        default=False,
                        action=argparse.BooleanOptionalAction,
                        help='Whether to use dot for address resolution')

    parser.add_argument('--dot_resolver', type=str,
                        default='1.1.1.1',
                        help='DNS server ip for DNS over TLS')

    parser.add_argument_group('Forward proxy arguments')

    parser.add_argument('--forward_proxy_address', type=str,
                        default=None,
                        help='Address of the forward proxy if any is present')

    parser.add_argument('--forward_proxy_port', type=int,
                        default=4433,
                        help='Port the forward proxy server runs on')

    parser.add_argument('--forward_proxy_mode', type=ProxyMode,
                        default=ProxyMode.HTTPS,
                        help='The proxy type of the forward proxy')

    parser.add_argument('--forward_proxy_resolve_address', type=bool,
                        default=False,
                        action=argparse.BooleanOptionalAction,
                        help='Whether to resolve domain before including it in eventual HTTP CONNECT request to second '
                             'proxy')

    return parser.parse_args()


def main():
    """
    Initializes command line parsing and starts a proxy.
    :return: None
    """
    args = initialize_parser()

    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

    setting = args.setting
    if setting == 0:
        proxy = Proxy(args.timeout, args.port, False, 20, False, args.dot_resolver,
                      ProxyMode.ALL, '127.0.0.1', 4434, ProxyMode.SNI,
                      False)
    elif setting == 1:
        proxy = Proxy(args.timeout, 4434, False, args.frag_size, False, args.dot_resolver,
                      ProxyMode.ALL, None, None, ProxyMode.HTTPS,
                      False)
    else:
        proxy = Proxy(args.timeout, args.port, args.record_frag, args.frag_size, args.dot, args.dot_resolver,
                      args.proxy_mode, args.forward_proxy_address, args.forward_proxy_port, args.forward_proxy_mode,
                      args.forward_proxy_resolve_address)
    proxy.start()


if __name__ == '__main__':
    main()
