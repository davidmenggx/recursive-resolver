from __future__ import annotations

import io
import struct
import socket
from typing import Self
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

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

class Serializable(ABC):
    @abstractmethod
    def to_bytes(self) -> bytes:
        pass

    @classmethod
    @abstractmethod
    def from_bytes(cls, reader: io.BytesIO) -> Self:
        pass

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
        result = 0 # 2 bytes in total
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
class DNSHeader(Serializable):
    id: int                 # transaction id: 2 bytes
    flags: DNSHeaderFlags
    qd_count: int = 0       # question record: 2 bytes
    an_count: int = 0       # answer record: 2 bytes
    ns_count: int = 0       # authority record: 2 bytes
    ar_count: int = 0       # additional record: 2 bytes

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

@dataclass
class DNSQuestion(Serializable):
    qname: str
    qtype: int = 1
    qclass: int = 1

    def to_bytes(self) -> bytes:
        encoded_qname = encode_domain_name(self.qname)
        encoded_qtype_qclass = struct.pack('!HH', self.qtype, self.qclass)
        return encoded_qname + encoded_qtype_qclass
    
    @classmethod
    def from_bytes(cls, reader: io.BytesIO) -> DNSQuestion:
        qname = decode_domain_name(reader)

        question_bytes = reader.read(4)
        qtype, qclass = struct.unpack('!HH', question_bytes)

        return DNSQuestion(qname, qtype, qclass)

@dataclass
class DNSRecord(Serializable):
    name: str
    type_: int = 1
    class_: int = 1
    ttl: int = 0
    rdlength: int = 4
    rdata: str = '0.0.0.0'

    def to_bytes(self) -> bytes:
        encoded_name = encode_domain_name(self.name)
        
        match self.type_:
            case 1: # check for type A: IPv4 address record
                encoded_rdata = socket.inet_aton(self.rdata)
            case 2 | 5: # check for type CNAME or NS
                encoded_rdata = encode_domain_name(self.rdata)
            case 28: # check for type AAAA: IPv6 address record
                encoded_rdata = socket.inet_pton(socket.AF_INET6, self.rdata)
            case _:
                encoded_rdata = bytes.fromhex(self.rdata)
        
        encoded_rdlength = len(encoded_rdata)

        packed_middle_fields = struct.pack('!HHIH', self.type_, self.class_, self.ttl, encoded_rdlength)

        return encoded_name + packed_middle_fields + encoded_rdata
    
    @classmethod
    def from_bytes(cls, reader: io.BytesIO) -> DNSRecord:
        name = decode_domain_name(reader)

        record_bytes = reader.read(10)
        _type, _class, ttl, rdlength = struct.unpack('!HHIH', record_bytes)

        match _type:
            case 1: # check for type A: IPv4 address record
                raw_rdata = reader.read(rdlength)
                rdata = socket.inet_ntoa(raw_rdata)
            case 2 | 5: # check for type CNAME or NS
                rdata = decode_domain_name(reader)
            case 28 if rdlength == 16: # check for type AAAA: IPv6 address record
                raw_rdata = reader.read(rdlength)
                rdata = socket.inet_ntop(socket.AF_INET6, raw_rdata)
            case _:
                raw_rdata = reader.read(rdlength)
                rdata = raw_rdata.hex()
        
        return DNSRecord(name, _type, _class, ttl, rdlength, rdata)

@dataclass
class DNSPacket(Serializable):
    header: DNSHeader
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    authorities: list[DNSRecord] = field(default_factory=list)
    additionals: list[DNSRecord] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        result = b''

        self.header.qd_count = len(self.questions)
        self.header.an_count = len(self.answers)
        self.header.ns_count = len(self.authorities)
        self.header.ar_count = len(self.additionals)

        result += self.header.to_bytes()
        
        for question in self.questions:
            result += question.to_bytes()
        
        for answer in self.answers:
            result += answer.to_bytes()

        for authority in self.authorities:
            result += authority.to_bytes()
        
        for additional in self.additionals:
            result += additional.to_bytes()

        return result
    
    @classmethod
    def from_bytes(cls, reader: io.BytesIO) -> DNSPacket:
        header = DNSHeader.from_bytes(reader)

        questions = []
        for _ in range(header.qd_count):
            questions.append(DNSQuestion.from_bytes(reader))
        
        answers = []
        for _ in range(header.an_count):
            answers.append(DNSRecord.from_bytes(reader))

        authorities = []
        for _ in range(header.ns_count):
            authorities.append(DNSRecord.from_bytes(reader))
        
        additionals = []
        for _ in range(header.ar_count):
            additionals.append(DNSRecord.from_bytes(reader))
        
        return DNSPacket(header, questions, answers, authorities, additionals)