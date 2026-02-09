import asyncio

from dns_parser import DNSPacket

async def send_query(packet: DNSPacket, nameserver: str, timeout: float = 5) -> DNSPacket:
    from connection_protocols import UpstreamProtocol
    loop = asyncio.get_running_loop()

    future = loop.create_future()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UpstreamProtocol(packet, future, nameserver),
        remote_addr=(nameserver, 53)
        )
    try:
        result: DNSPacket = await asyncio.wait_for(future, timeout)
        return result
    finally:
        transport.close()