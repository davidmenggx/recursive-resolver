import random
import asyncio
from copy import deepcopy

from dns_parser import DNSPacket, DNSQuestion, DNSRecord

def find_ip_in_records(records: list[DNSRecord], ns_name: str, recursive_response: bool = False) -> str:
    for record in records:
        # Check for glue records to not get stuck in an infinite loop
        if record.type_ == 1 and (recursive_response or record.name == ns_name):
            return record.rdata
    return ''

def construct_new_question(ns_name: str, packet: DNSPacket) -> DNSPacket:
    new_packet = deepcopy(packet)
    new_packet.header.flags.rd = 0 # this is unneeded in theory but its good to manually unwind the recursion
    new_packet.header.id = random.randint(0, 65535)
    new_packet.questions = [DNSQuestion(ns_name)]
    return new_packet

def is_subdomain(sub: str, parent: str) -> bool:
    """
    Implement Bailiwick checking:
    Check if the returned domain is a subdomain of the queried server
    """
    sub = sub.strip('.')
    parent = parent.strip('.')

    return (sub == parent) or (sub.endswith("." + parent)) or (sub.endswith(parent))

async def parse_nameservers(response: DNSPacket, packet: DNSPacket, current_zone: str, depth: int = 1) -> list[str]:
    
    from resolve import resolve

    result = []
    ip_found = False # Don't resolve nameservers if glue records are already found

    for authority in response.authorities:                                          # Authorities section contains information on next servers to lookup
        if authority.type_ == 2:                                                    # for simplicity, only consider name servers for next hop
            ns_name = authority.name                                                # what zone I am trying to lookup, for example edu.
            target_server = authority.rdata                                         # target nameserver for next hop
            if is_subdomain(target_server, current_zone):                           # Bailiwick check
                if ip := find_ip_in_records(response.additionals, target_server):   # Fast path: check for glue record
                    result.append(ip)
                    ip_found = True
                elif not ip_found:
                    new_packet = construct_new_question(target_server, packet)
                    ip_packet = await resolve(new_packet, depth + 1)
                    ip = find_ip_in_records(ip_packet.answers, ns_name, recursive_response=True)
                    if ip:
                        result.append(ip)
    return result

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

def verify_final_answer(response: DNSPacket, client_response_type: int) -> bool:
    # loop through the responses and make sure that the response type matches the client question type
    for answer in response.answers:
        if answer.type_ == client_response_type:
            return True
    return False

async def resolve(client_packet: DNSPacket, depth: int  = 0) -> DNSPacket:
    # check depth
    if depth > 10: # make this not hard coded in the future
        print('MAX DEPTH REACHED!!!')
        return DNSPacket.create_error(client_packet.header.id, rcode=2)
    
    if not client_packet.questions: # make sure no malformed messages have reached this point
        return DNSPacket.create_error(client_packet.header.id, rcode=1)
    
    current_nameservers: list[str] = ['198.41.0.4'] # a.root-servers.net - Verisign

    current_zone = '.'
    
    while True:
        success = False
        for server in current_nameservers:
            try:
                response: DNSPacket = await send_query(client_packet, timeout=5, nameserver=server)
            except Exception:
                continue # if the current nameserver cannot be connected, keep trying other nameservers

            success = True
            
            if response.header.flags.rcode == 3:
                # important: there needs to be a line here saving the nxdomain to cache to avoid future lookups
                print('NXDOMAIN')
                return DNSPacket.create_error(client_packet.header.id, rcode=3)
            
            if response.header.flags.rcode != 0:
                print('ERROR! Server failure!')
                continue
            
            if response.header.an_count > 0:
                print('FOUND POTENTIAL ANSWER!')
                if verify_final_answer(response, client_packet.questions[0].qtype): # make sure that indexing like this is safe
                    print('FOUND FINAL ANSWER!')
                    return response
                else:
                    # make sure that we look down the new correct type for response here
                    cname_record = next((ans for ans in response.answers if ans.type_ == 5), None)
                    if cname_record:
                        print(f"Following CNAME: {cname_record.rdata}")

                        # looks a lot like construct_new_question(), maybe refactor / combine
                        new_packet = deepcopy(client_packet)
                        new_packet.header.flags.rd = 0 # this is unneeded in theory but its good to manually unwind the recursion
                        new_packet.questions[0].qname = cname_record.rdata
                        new_packet.questions[0].qtype = 1

                        final_ip_packet = await resolve(new_packet, depth + 1)
                        
                        for answer in final_ip_packet.answers:
                            response.answers.append(answer)
                        
                        return response
            
            if response.header.ns_count > 0 and response.authorities:
                print('FOUND NAMESERVER(s)')
                current_nameservers = await parse_nameservers(
                    response=response, 
                    packet=client_packet, 
                    current_zone=current_zone, 
                    depth=depth
                    )
                current_zone = response.authorities[0].name
                break

        if not success:
            print('Parsing not successful for all nameservers')
            return DNSPacket.create_error(client_packet.header.id, rcode=2)