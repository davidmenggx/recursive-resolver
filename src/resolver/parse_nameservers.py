import random
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