import random
from copy import deepcopy

from dns_parser import DNSPacket, DNSQuestion, DNSRecord

def find_ip_in_records(records: list[DNSRecord], ns_name: str, recursive_response: bool = False) -> str:
    for record in records:
        if record.type_ == 1 and (recursive_response or record.name == ns_name):
            return record.rdata
    return ''

def construct_new_question(ns_name: str, packet: DNSPacket) -> DNSPacket:
    new_packet = deepcopy(packet)
    new_packet.header.flags.rd = 0 # this is unneeded in theory but its good to manually unwind the recursion
    new_packet.header.id = random.randint(0, 65535)
    new_packet.questions = [DNSQuestion(ns_name)]
    return new_packet

async def parse_nameservers(response: DNSPacket, packet: DNSPacket, depth: int = 1) -> list[str]:
    from resolve import resolve
    result = []
    ip_found = False
    for authority in response.authorities:
        if authority.type_ == 2:
            ns_name = authority.name
            target_server = authority.rdata
            if ip := find_ip_in_records(response.additionals, target_server):
                result.append(ip)
                ip_found = True
            elif not ip_found:
                new_packet = construct_new_question(target_server, packet)
                ip_packet = await resolve(new_packet, depth + 1)
                ip = find_ip_in_records(ip_packet.answers, ns_name, recursive_response=True)
                if ip:
                    result.append(ip)
    return result