from dns_parser import DNSPacket

class Cache:
    def __init__(self):
        self.cache: dict[tuple[str, int], DNSPacket] = {} # maps (domain name, type) -> address

    def get(self, domain_name: str, type: int) -> DNSPacket | None:
        return self.cache.get((domain_name, type))
    
    def put(self, domain_name: str, type: int, response: DNSPacket) -> None:
        self.cache[(domain_name, type)] = response

DNSCache = Cache()