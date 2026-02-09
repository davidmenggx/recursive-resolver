from dns_parser import DNSPacket

from send_query import send_query
from parse_nameservers import parse_nameservers

async def resolve(packet: DNSPacket, depth: int  = 0) -> DNSPacket:
    # check depth
    if depth > 10: # make this not hard coded in the future
        print('MAX DEPTH REACHED!!!')
        return DNSPacket.create_error(packet.header.id, rcode=2)
    
    current_nameservers: list[str] = ['198.41.0.4']

    while True:
        success = False
        for server in current_nameservers:
            try:
                response: DNSPacket = await send_query(packet, timeout=5, nameserver=server)
            except Exception:
                continue

            success = True
            
            if response.header.flags.rcode == 3:
                print('NXDOMAIN')
                return DNSPacket.create_error(packet.header.id, rcode=3)
            
            if response.header.flags.rcode != 0:
                print('ERROR! Server failure!')
                continue
            
            if response.header.an_count > 0:
                print('FOUND FINAL ANSWER!')
                return response
            
            if response.header.ns_count > 0 and response.authorities:
                print('FOUND NAMESERVER(s)')
                current_nameservers = await parse_nameservers(response, packet, depth)
                break

        if not success:
            print('Parsing not successful for all nameservers')
            return DNSPacket.create_error(packet.header.id, rcode=2)