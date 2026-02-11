from copy import deepcopy

from dns_parser import DNSPacket
from send_query import send_query
from parse_nameservers import parse_nameservers

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
    
    current_nameservers: list[str] = ['198.41.0.4']

    while True:
        success = False
        for server in current_nameservers:
            try:
                response: DNSPacket = await send_query(client_packet, timeout=5, nameserver=server)
            except Exception:
                continue

            success = True
            
            if response.header.flags.rcode == 3:
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
                current_nameservers = await parse_nameservers(response, client_packet, depth)
                break

        if not success:
            print('Parsing not successful for all nameservers')
            return DNSPacket.create_error(client_packet.header.id, rcode=2)