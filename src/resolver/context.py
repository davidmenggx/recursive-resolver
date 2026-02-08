import io
import socket
import struct
import selectors
from enum import Enum

from protocol import DNSPacket, DNSRecord

class ProcessingState(Enum):
    PROCESSING_MESSAGE = 'PROCESSING_MESSAGE'
    WAITING_FOR_RESPONSE = 'WAITING_FOR_RESPONSE'
    FINISHED = 'FINISHED'

class Context:
    def __init__(
            self, 
            sel: selectors.BaseSelector, 
            server_sock: socket.socket,
            client_address: tuple[str, int], 
            original_query: DNSPacket
            ) -> None:
        # Connection information:
        self.sel: selectors.BaseSelector = sel
        self.server_sock: socket.socket = server_sock
        self.client_address: tuple[str, int] = client_address

        # Request information:
        self.original_query: DNSPacket = original_query
        try:
            self.original_query_bytes = self.original_query.to_bytes()
        except (ValueError, struct.error, IndexError):
            self.response = DNSPacket.create_error(self.original_query.header.id, rcode=1)
            self.finish_resolution()
            print("Sent Format Error (RCODE 1) to client.")
        self.client_wants_recursion: bool = (self.original_query.header.flags.rd == 1)

        # Current state:
        self.state = ProcessingState.PROCESSING_MESSAGE                 # Track the current processing state
        self.response: DNSPacket | None = None                          # Track the current response from upstream server
        self.current_nameserver = '198.41.0.4'                          # Track the current nameserver attemping to reach, start with root server
        self.current_transaction_id = self.original_query.header.id
        self.depth = 0                                                  # Prevent infinite loops

        self.original_query.header.flags.rd = 0

    def process(self):
        match self.state:
            case ProcessingState.PROCESSING_MESSAGE:
                self.resolve()
            case ProcessingState.FINISHED:
                self.send_response()
    
    def handle_upstream_response(self, sock: socket.socket):
        print('New connection!')
        self.sel.unregister(sock)
        
        data, addr = sock.recvfrom(4096)

        sock.close()

        try:
            self.response = DNSPacket.from_bytes(io.BytesIO(data))
        except (ValueError, struct.error, IndexError):
            if len(data) >= 2:
                transaction_id = struct.unpack('!H', data[:2])[0]
                self.response = DNSPacket.create_error(transaction_id, rcode=1)
                self.finish_resolution()
                print("Sent Format Error (RCODE 1) to client.")
            return

        self.state = ProcessingState.PROCESSING_MESSAGE

        self.process()
    
    def check_cache(self, ): # IMPORTANT: FILL THIS IN
        ...
    
    def find_referral_ip(self, additional_records: list[DNSRecord]) -> str:
        for record in additional_records:
            if record.type_ == 1:
                return record.rdata
        return '' # THIS NEEDS TO SUPPORT NS RECORDS AND IPV6
    
    def send_request_upstream(self):
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            upstream_socket.sendto(self.original_query_bytes, (self.current_nameserver, 53))

            self.sel.register(upstream_socket, selectors.EVENT_READ, self.handle_upstream_response)

            self.state = ProcessingState.WAITING_FOR_RESPONSE

            self.depth += 1
        except OSError:
            self.return_server_error(rcode=2)
            print('Internal server error')
    
    def resolve(self) -> None:
        if self.depth > 10:
            self.return_server_error(rcode=2)
            print('ERROR! Maximum recursion depth reached!')

        print('Resolving!')

        self.check_cache() # figure this out

        if self.response:
            if self.response.header.flags.rcode != 0:
                if self.response.header.flags.rcode == 3:
                    print('NXDOMAIN')
                    self.return_server_error(rcode=3)
                else:
                    print('ERROR! Server failure!')
                    self.return_server_error(rcode=2)
                return

            if self.response.header.an_count > 0 or not self.client_wants_recursion:
                print('FOUND!')
                self.finish_resolution()
                return
            
            if self.response.header.ns_count > 0 and self.response.authorities:
                self.current_nameserver = self.find_referral_ip(self.response.additionals)
                if not self.current_nameserver:
                    self.return_server_error(rcode=2)
                    print("COULDN'T FIND NEXT NAME SERVER")
                    return
        
        self.send_request_upstream()

    def return_server_error(self, rcode: int =2) -> None:
        self.response = DNSPacket.create_error(self.original_query.header.id, rcode=rcode)
        self.finish_resolution()

    def finish_resolution(self) -> None:
        self.state = ProcessingState.FINISHED
        self.send_response()
    
    def send_response(self) -> None:
        try:
            if self.response:
                self.response.header.id = self.original_query.header.id
            else:
                self.response = DNSPacket.create_error(self.original_query.header.id, rcode=2)
            serialized_response = self.response.to_bytes()
            self.server_sock.sendto(serialized_response, self.client_address)
        except Exception as e:
            print(f'Unexpected failure sending response back to client, dropping packet: {e}')
        finally:
            self.cleanup_all_sockets()
    
    def cleanup_all_sockets(self) -> None:
        try:
            self.sel.unregister(self.server_sock)
            self.server_sock.close()
        except Exception:
            pass