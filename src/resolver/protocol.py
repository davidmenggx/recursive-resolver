from __future__ import annotations

import io
import struct
from dataclasses import dataclass, astuple

def encode_domain_name(domain_name: str) -> bytes:
    encoded_bytes = b''
    labels = domain_name.strip('.').split('.') # remove leading/trailing full stops and create list of labels

    for label in labels:
        length = len(label)

        if length > 63: # each label cannot be longer than 63 octets - RFC 1035
            raise ValueError(f'Label cannot be longer than 63 octets, currently {length} octects')
        if length == 0:
            raise ValueError('Label cannot be empty (cannot have consecutive full stops)')
        
        encoded_bytes += bytes([length]) # need [] or else constructor creates zero-bytes of the specified length
        encoded_bytes += label.encode('ascii')
    
    encoded_bytes += b'\x00' # root terminator

    if (output_length := len(encoded_bytes)) > 255:
        raise ValueError(f'Domain cannot be longer than 255 octects, currently {output_length} octects')
    
    return encoded_bytes

def decode_domain_name(reader: io.BytesIO, depth: int = 0) -> str:
    if depth > 10:
        raise ValueError('Reached maximum recursion depth, likely pointer loop')
    
    labels = []
    while True:
        byte1 = reader.read(1)

        if not byte1 or byte1 == b'\x00':
            break

        if (byte1[0] & 0xC0) == 0xC0: # bit mask using 0xC0 = 11000000
            byte2 = reader.read(1)
            # calculate two byte offset: first strip away 11 flag using & 0x3F 
            # then combine first byte with second byte for full offset
            offset = ((byte1[0] & 0x3F) << 8) | byte2[0]
            current_position = reader.tell()

            reader.seek(offset)
            res = decode_domain_name(reader, depth+1) # recursively call for pointers
            reader.seek(current_position)

            labels.append(res)
            break
        else:
            length = byte1[0]

            if length > 63: # each label cannot be longer than 63 octets - RFC 1035
                raise ValueError(f'Label cannot be longer than 63 octets, currently {length} octects')
            
            result_label = reader.read(length)
            ascii_label = result_label.decode('ascii')
            labels.append(ascii_label)
    return '.'.join(labels)

@dataclass
class DNSHeaderFlags:
    # flags: 2 bytes combined
    qr: int = 0         # query: 1 bit
    opcode: int = 0     # opcode: 4 bits
    aa: int = 0         # authoritative answer: 1 bit
    tc: int = 0         # truncation: 1 bit
    rd: int = 0         # recursion desired: 1 bit
    ra: int = 0         # recursion available: 1 bit
    z: int = 0          # reserved, 3 bits
    rcode: int = 0      # response code: 4 bits

    def pack_flags(self) -> int:
        result = 0
        result |= (self.qr & 0x01) << 15        # mask 1 bit value with 0x01 = 00000001
        result |= (self.opcode & 0x0F) << 11    # mask 4 bit value with 0x0F = 00001111
        result |= (self.aa & 0x01) << 10
        result |= (self.tc & 0x01) << 9
        result |= (self.rd & 0x01) << 8
        result |= (self.ra & 0x01) << 7
        result |= (self.z & 0x07) << 4          # mask 3 bit value with 0x07 = 00000111
        result |= (self.rcode & 0x0F)
        return result
    
    @classmethod
    def unpack_flags(cls, raw_int: int) -> DNSHeaderFlags:
        qr = (raw_int >> 15) & 0x01
        opcode = (raw_int >> 11) & 0x0F
        aa = (raw_int >> 10) & 0x01
        tc = (raw_int >> 9) & 0x01
        rd = (raw_int >> 8) & 0x01
        ra = (raw_int >> 7) & 0x01
        z = (raw_int >> 4) & 0x07
        rcode = raw_int & 0x0F
        return DNSHeaderFlags(qr, opcode, aa, tc, rd, ra, z, rcode)

@dataclass
class DNSHeader:
    id: int                 # transaction id: 2 bytes
    flags: DNSHeaderFlags
    qd_count: int           # question record: 2 bytes
    an_count: int           # answer record: 2 bytes
    ns_count: int           # authority record: 2 bytes
    ar_count: int           # additional record: 2 bytes

    def to_bytes(self) -> bytes:
        return struct.pack(
            '!6H', # big endian, 12 bytes long (aka 6 unsigned shorts)
            self.id,
            self.flags.pack_flags(),
            self.qd_count,
            self.an_count,
            self.ns_count,
            self.ar_count
            )
    
    @classmethod
    def from_bytes(cls, reader: io.BytesIO) -> DNSHeader:
        header_bytes = reader.read(12) # DNS header is 12 bytes long - RFC 1035
        unpacked_header = struct.unpack('!6H', header_bytes)
        id, flags_raw, qd_count, an_count, ns_count, ar_count = unpacked_header
        flags = DNSHeaderFlags.unpack_flags(flags_raw)
        return DNSHeader(id, flags, qd_count, an_count, ns_count, ar_count)

class DNSQuestion:
    ...

class DNSRecord:
    ...

class DNSPacket:
    ...

