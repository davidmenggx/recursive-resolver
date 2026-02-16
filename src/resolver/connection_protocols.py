import io
import asyncio
from typing import override

from resolve import resolve
from dns_parser import DNSPacket

class ServerProtocol(asyncio.DatagramProtocol):
    @override
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        print('Server connected')
    
    @override
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.addr = addr

        try:
            query = DNSPacket.from_bytes(io.BytesIO(data))
        except Exception:
            return # silently drop failed parse
        
        # schedule the query to be handled in the event loop
        # handle_query is needed since async function is needed to await resolve
        asyncio.create_task(self.handle_query(query))
    
    async def handle_query(self, packet: DNSPacket):
        if self.transport:
            packet.header.flags.rd = 0 # LOOK INTO THIS: perhaps keep whether the client wanted recursion so +norecurse works

            response = await resolve(packet)

            serialized_response = response.to_bytes()
            self.transport.sendto(serialized_response, self.addr)

    @override
    def error_received(self, exc: Exception) -> None:
        # Typically handle client side issues like destination unreachable
        if self.addr:
            print(f'Client {self.addr} error: {exc}')
        else:
            print(f'Client (unknown address) error: {exc}')

    @override
    def connection_lost(self, exc: Exception | None) -> None:
        # Handles cleanup for end of lifecycle
        # Abnormal closures will have an Exception object, otherwise clean shutdown so unregister the transport
        if exc:
            print(f'SERVER CLOSED WITH ERROR: {exc}')
        self.transport = None

class UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, packet: DNSPacket, future: asyncio.Future, nameserver: str = '198.41.0.4'):
        self.packet: DNSPacket = packet
        self.future = future
        self.nameserver = nameserver
    
    @override
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        try:
            query = DNSPacket.to_bytes(self.packet)
            self.transport.sendto(query, addr=(self.nameserver, 53))
        except Exception as e:
            # Set an exception to stop the upstream future from waiting forever
            self.future.set_exception(e)
            self.transport.close()
    
    @override
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        print(f'Datagram received: {addr}')
        try:
            response = DNSPacket.from_bytes(io.BytesIO(data))
            self.future.set_result((response, addr))
        except Exception:
            self.future.set_exception(ValueError("Bad upstream packet"))
        
        if self.transport:
            self.transport.close()
    
    @override
    def error_received(self, exc: Exception) -> None:
        self.future.set_exception(exc)
        if self.transport:
            self.transport.close()
        print(f'Upstream server {self.nameserver} error: {exc}')
    
    @override
    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            print(f'Upstream connection closed with error: {exc}')
        self.transport = None