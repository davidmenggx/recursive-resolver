import socket
import selectors

def main():
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        listening_socket.bind(('127.0.0.1', 8053))
    except OSError as e:
        raise RuntimeError(f"Failed to bind to port {8053}: {e}")

    listening_socket.setblocking(False)

    sel = selectors.DefaultSelector()
    sel.register(listening_socket, selectors.EVENT_READ, data='Listener')
    
    try:
        while True:
            events = sel.select(timeout=1.0)
            ...
    except KeyboardInterrupt:
        pass
    finally:
        sel.close()
        listening_socket.close()

if __name__ == '__main__':
    main()