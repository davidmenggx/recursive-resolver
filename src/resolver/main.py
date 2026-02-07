import io
import socket
import selectors
import functools

from context import Context
from protocol import DNSPacket

def handle_new_request(sock: socket.socket, selector: selectors.BaseSelector) -> None:
    try:
        data, addr = sock.recvfrom(512) # Standard limit for DNS packets is 512 bytes - RFC 1035
        if not data:
            return

        dns_message = DNSPacket.from_bytes(io.BytesIO(data))
        
        request_context = Context(selector, sock, addr, dns_message)
        request_context.process()   
    except BlockingIOError:
        pass

def main(ip: str = '127.0.0.1', port: int = 8053):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((ip, port))
    except OSError as e:
        raise RuntimeError(f"Failed to bind to port {port}: {e}")

    server_socket.setblocking(False)

    sel = selectors.DefaultSelector()
    sel.register(server_socket, selectors.EVENT_READ, data=functools.partial(handle_new_request, selector=sel))

    print('server up')
    try:
        while True:
            events = sel.select(timeout=1.0)
            for key, mask in events:
                key.data(key.fileobj)
    except KeyboardInterrupt:
        print('server down')
        pass
    finally:
        sel.close()
        server_socket.close()

if __name__ == '__main__':
    main()