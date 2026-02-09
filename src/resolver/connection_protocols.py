import io
import asyncio

from resolve import resolve
from dns_parser import DNSPacket

class ClientProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        print('Server connected')
    
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            query = DNSPacket.from_bytes(io.BytesIO(data))
        except Exception:
            return # silently drop failed parse
        
        asyncio.create_task(self.handle_query(query, addr))
        
    async def handle_query(self, packet: DNSPacket, addr: tuple[str, int]):
        packet.header.flags.rd = 0
        response = await resolve(packet)
        serialized_response = response.to_bytes()
        self.transport.sendto(serialized_response, addr)

class UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, packet: DNSPacket, future: asyncio.Future, nameserver: str = '198.41.0.4'):
        self.packet: DNSPacket = packet
        self.future = future
        self.nameserver = nameserver
    
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        try:
            query = DNSPacket.to_bytes(self.packet)
            self.transport.sendto(query, addr=(self.nameserver, 53))
        except Exception as e:
            self.future.set_exception(e)
            self.transport.close()
    
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            response = DNSPacket.from_bytes(io.BytesIO(data))
            self.future.set_result(response)
        except Exception:
            self.future.set_exception(ValueError("Bad upstream packet"))        
        
        self.transport.close()
    
    def error_received(self, exc: Exception) -> None:
        self.future.set_exception(exc)
        self.transport.close()