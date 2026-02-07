import io
import socket
import struct
import selectors
from enum import Enum

from protocol import DNSPacket

class ProcessingState(Enum):
    PROCESSING_MESSAGE = 'PROCESSING_MESSAGE'
    WAITING_FOR_RESPONSE = 'WAITING_FOR_RESPONSE'
    FINISHED = 'FINISHED'

class Context:
    def __init__(
            self, sel: selectors.BaseSelector, 
            server_sock: socket.socket,
            client_address: tuple[str, int], 
            original_query: DNSPacket
            ) -> None:
        
        self.sel: selectors.BaseSelector = sel
        self.server_sock: socket.socket = server_sock
        self.client_address: tuple = client_address
        self.original_query: DNSPacket = original_query
        self.response: DNSPacket | None = None
        self.state = ProcessingState.PROCESSING_MESSAGE
        self.current_nameserver = '198.41.0.4'
        self.depth = 0 # maximum recursion depth
        self.client_wants_recursion = (self.original_query.header.flags.rd == 1)

    def process(self):
        match self.state:
            case ProcessingState.PROCESSING_MESSAGE:
                self.resolve()
            case ProcessingState.FINISHED:
                self.send_response()
            case _:
                pass
    
    def handle_upstream_response(self, sock: socket.socket):
        print('New connection!')
        self.sel.unregister(sock)
        
        data, addr = sock.recvfrom(512) # Standard limit for DNS packets is 512 bytes - RFC 1035

        sock.close()

        try:
            self.response = DNSPacket.from_bytes(io.BytesIO(data))
        except (ValueError, struct.error, IndexError):
            if len(data) >= 2:
                transaction_id = struct.unpack('!H', data[:2])[0]
                self.response = DNSPacket.create_simple_error(transaction_id, rcode=1)
                self.finish_resolution()
                print("Sent Format Error (RCODE 1) to client.")
            return

        self.state = ProcessingState.PROCESSING_MESSAGE

        self.process()
    
    def resolve(self) -> None:
        if self.depth > 10:
            self.response = DNSPacket.create_simple_error(self.original_query.header.id, rcode=2)
            self.finish_resolution()
            print('ERROR! Maximum recursion depth reached!')

        print('Resolving!')
        # check the cache or forward to server
        if self.response: 
            if self.response.header.flags.rcode != 0:
                self.response = DNSPacket.create_simple_error(self.original_query.header.id, rcode=2)
                self.finish_resolution()
                print('ERROR! Server failure!')
                return

            if self.response.header.an_count > 0:
                self.finish_resolution()
                print('FOUND!')
                return
            
            elif self.response.header.ns_count > 0 and self.response.authorities:
                name_server_found = False
                for record in self.response.additionals:
                    if record.type_ == 1:
                        self.current_nameserver = record.rdata
                        name_server_found = True
                        break
                if not name_server_found:
                    self.response = DNSPacket.create_simple_error(self.original_query.header.id, rcode=2)
                    self.send_response()
                    print("COULDN'T FIND NEXT NAME SERVER")
                    return # think about what happens here... set the rcode to 2... retry?
            
            else:
                self.response = DNSPacket.create_simple_error(self.original_query.header.id, rcode=2)
                self.finish_resolution()
                print('Server failure')
                return

        if not self.client_wants_recursion:
            self.finish_resolution()
            return
        
        self.original_query.header.flags.rd = 0
        
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            original_query = self.original_query.to_bytes()
        except (ValueError, struct.error, IndexError):
            self.response = DNSPacket.create_simple_error(self.original_query.header.id, rcode=1)
            self.finish_resolution()
            print("Sent Format Error (RCODE 1) to client.")
            return

        try:
            upstream_socket.sendto(original_query, (self.current_nameserver, 53))

            self.sel.register(upstream_socket, selectors.EVENT_READ, self.handle_upstream_response)

            self.state = ProcessingState.WAITING_FOR_RESPONSE

            self.depth += 1
        except OSError:
            print('Internal server error')
            ... # GENERATE INTERNAL SERVER ERROR
    
    def send_response(self) -> None:
        response = self.response
        if response:
            response.header.id = self.original_query.header.id
            response = response.to_bytes()
            self.server_sock.sendto(response, self.client_address)
        # there is an error path here too!
    
    def finish_resolution(self) -> None:
        self.state = ProcessingState.FINISHED
        self.send_response()