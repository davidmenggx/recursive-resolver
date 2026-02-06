import io
import pytest

from resolver.protocol import encode_domain_name, decode_domain_name, DNSHeaderFlags, DNSHeader, DNSQuestion, DNSRecord, DNSPacket

# Encoder tests:
def test_successful_encode():
    domain = 'www.test.com'
    expected_bytes = b'\x03www\x04test\x03com\x00'
    expected_hex = '03 77 77 77 04 74 65 73 74 03 63 6f 6d 00'

    assert encode_domain_name(domain) == expected_bytes
    assert encode_domain_name(domain).hex(' ') == expected_hex

@pytest.mark.parametrize("invalid_input", [
    'www..test.com',
    '',
    'www.test.com' * 30
])
def test_failed_encode(invalid_input):
    with pytest.raises(ValueError):
        encode_domain_name(invalid_input)

# Decoder tests:
def test_successful_decode():
    buffered_domain = b'\x03www\x04test\x03com\x00'
    buffer = io.BytesIO(buffered_domain)
    expected = 'www.test.com'

    assert decode_domain_name(buffer) == expected

def test_compressed_decode():
    compressed_domain = b'\x03www\x04test\x03com\x00\x03api\xc0\x04\xff\xff\x00'
    buffer = io.BytesIO(compressed_domain)
    buffer.seek(14)
    expected = 'api.test.com'

    assert decode_domain_name(buffer) == expected

def test_compression_loop_decode():
    malicious_domain = b'\xc0\x00'
    buffer = io.BytesIO(malicious_domain)
    
    with pytest.raises(ValueError):
        decode_domain_name(buffer)

def test_empty_decode():
    empty_domain = b'\x00'
    buffer = io.BytesIO(empty_domain)
    expected = ''

    assert decode_domain_name(buffer) == expected

def test_single_label_decode():
    single_label_domain = b'\x03www\x00'
    buffer = io.BytesIO(single_label_domain)
    expected = 'www'

    assert decode_domain_name(buffer) == expected

# DNSHeaderFlags tests:
@pytest.mark.parametrize('qr,opcode,rcode,expected', [
    (1, 0, 0, 0x8000),
    (0, 4, 0, 0x2000),
    (0, 0, 3, 0x0003),
])
def test_valid_flag_pack(qr, opcode, rcode, expected):
    f = DNSHeaderFlags(qr=qr, opcode=opcode, rcode=rcode)
    assert f.pack_flags() == expected

@pytest.mark.parametrize('raw_int,expected', [
    (0x8000, DNSHeaderFlags(qr=1, opcode=0, rcode=0)),
    (0x2000, DNSHeaderFlags(qr=0, opcode=4, rcode=0)),
    (0x0003, DNSHeaderFlags(qr=0, opcode=0, rcode=3))
])
def test_valid_flag_unpack(raw_int, expected):
    assert DNSHeaderFlags.unpack_flags(raw_int=raw_int) == expected # __eq__ is supported because DNSHeaderFlags is a dataclass

# DNSHeader tests:
def test_valid_header_to_bytes():
    flags_input = DNSHeaderFlags(qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0)
    header = DNSHeader(
        id=0x1234, 
        flags=flags_input, 
        qd_count=1, 
        an_count=0, 
        ns_count=0, 
        ar_count=0
    )
    expected_output = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'

    assert header.to_bytes() == expected_output

def test_valid_header_from_bytes():
    input = b'\xaa\xaa\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
    buffer = io.BytesIO(input)

    expected_flags = DNSHeaderFlags(qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0)
    expected = DNSHeader(
        id=0xAAAA, 
        flags=expected_flags, 
        qd_count=1, 
        an_count=1, 
        ns_count=0, 
        ar_count=0
    )

    assert DNSHeader.from_bytes(buffer) == expected

def test_valid_long_header_from_bytes():
    # this input has extraneous bytes at the end that should not be parsed
    input = b'\xaa\xaa\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x00\x01\x00'
    buffer = io.BytesIO(input)

    expected_flags = DNSHeaderFlags(qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0)
    expected = DNSHeader(
        id=0xAAAA, 
        flags=expected_flags, 
        qd_count=1, 
        an_count=1, 
        ns_count=0, 
        ar_count=0
    )

    assert DNSHeader.from_bytes(buffer) == expected

# DNSQuestion test:
def test_valid_question_to_bytes():
    question = DNSQuestion('www.google.com', 1, 1)
    expected = b'\x03www\x06google\x03com\x00\x00\x01\x00\x01'

    assert question.to_bytes() == expected

def test_valid_question_from_bytes():
    input = b'\x03www\x06google\x03com\x00\x00\x01\x00\x01'
    buffer = io.BytesIO(input)

    expected = DNSQuestion(qname='www.google.com', qtype=1, qclass=1)

    assert DNSQuestion.from_bytes(buffer) == expected

def test_valid_long_question_from_bytes():
    # this input has extraneous bytes at the end that should not be parsed
    input = b'\x03www\x06google\x03com\x00\x00\x01\x00\x01\x01\x00\x01'
    buffer = io.BytesIO(input)

    expected = DNSQuestion(qname='www.google.com', qtype=1, qclass=1)

    assert DNSQuestion.from_bytes(buffer) == expected

# DNSRecord test:
def test_valid_record_to_bytes():
    record = DNSRecord('www.google.com', 1, 1, 300, 4, '8.8.8.8')
    expected = b'\x03www\x06google\x03com\x00\x00\x01\x00\x01\x00\x00\x01,\x00\x04\x08\x08\x08\x08'

    assert record.to_bytes() == expected

def test_valid_record_from_bytes():
    input = b'\x03www\x06google\x03com\x00\x00\x01\x00\x01\x00\x00\x01,\x00\x04\x08\x08\x08\x08'
    buffer = io.BytesIO(input)

    expected = DNSRecord('www.google.com', 1, 1, 300, 4, '8.8.8.8')

    assert DNSRecord.from_bytes(buffer) == expected

# DNSPacket test:
def test_valid_message_to_bytes():
    flags = DNSHeaderFlags(qr=1, opcode=0, rd=1, ra=1, rcode=0)
    header = DNSHeader(43707, flags=flags, qd_count=1, an_count=1)
    question = DNSQuestion('example.com', 1, 1)
    answer = DNSRecord('example.com', 1, 1, 300, 4, '93.184.216.34')
    
    input = DNSPacket(header, questions=[question], answers=[answer])

    expected = b'\xaa\xbb\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22'
    
    assert input.to_bytes() == expected

def test_valid_message_from_bytes():
    input = b'\xaa\xbb\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22'
    buffer = io.BytesIO(input)

    expected_flags = DNSHeaderFlags(qr=1, opcode=0, rd=1, ra=1, rcode=0)
    expected_header = DNSHeader(43707, flags=expected_flags, qd_count=1, an_count=1)
    expected_question = DNSQuestion('example.com', 1, 1)
    expected_answer = DNSRecord('example.com', 1, 1, 300, 4, '93.184.216.34')
    
    expected = DNSPacket(expected_header, questions=[expected_question], answers=[expected_answer])

    assert DNSPacket.from_bytes(buffer) == expected

def test_valid_long_message_to_bytes():
    flags = DNSHeaderFlags(qr=1, opcode=0, rd=1, ra=1, rcode=0)
    header = DNSHeader(43707, flags=flags, qd_count=1, an_count=2, ns_count=1, ar_count=1)
    question = DNSQuestion('example.com', 1, 1)
    answer1 = DNSRecord('example.com', 1, 1, 300, 4, '93.184.216.34')
    answer2 = DNSRecord('example.com', 1, 1, 300, 4, '93.184.216.35')
    authority = DNSRecord(name='example.com', _type=2, _class=1, ttl=86400, rdlength=17, rdata='ns1.example.com')
    additional = DNSRecord(name='ns1.example.com', _type=1, _class=1, ttl=300, rdlength=4, rdata='10.0.0.1')

    input = DNSPacket(
        header, 
        questions=[question],
        answers=[answer1, answer2],
        authorities=[authority],
        additionals=[additional]
    )

    expected = (
    # Header
    b'\xaa\xbb\x81\x80\x00\x01\x00\x02\x00\x01\x00\x01'
    # Question: example.com
    b'\x07example\x03com\x00\x00\x01\x00\x01'
    # Answer 1: example.com -> 93.184.216.34
    b'\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22'
    # Answer 2: example.com -> 93.184.216.35
    b'\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x23'
    # Authority: example.com -> NS ns1.example.com
    b'\x07example\x03com\x00\x00\x02\x00\x01\x00\x01\x51\x80\x00\x11\x03ns1\x07example\x03com\x00'
    # Additional: ns1.example.com -> 10.0.0.1
    b'\x03ns1\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x0a\x00\x00\x01'
    )

    assert input.to_bytes() == expected

def test_valid_long_message_from_bytes():
    input = (
    # Header
    b'\xaa\xbb\x81\x80\x00\x01\x00\x02\x00\x01\x00\x01'
    # Question: example.com
    b'\x07example\x03com\x00\x00\x01\x00\x01'
    # Answer 1: example.com -> 93.184.216.34
    b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22'
    # Answer 2: example.com -> 93.184.216.35
    b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x23'
    # Authority: example.com -> NS ns1.example.com
    b'\xc0\x0c\x00\x02\x00\x01\x00\x01\x51\x80\x00\x06\x03ns1\xc0\x0c'
    # Additional: ns1.example.com -> 10.0.0.1
    b'\x03ns1\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x0a\x00\x00\x01'
    )
    buffer = io.BytesIO(input)

    expected_flags = DNSHeaderFlags(qr=1, opcode=0, rd=1, ra=1, rcode=0)
    expected_header = DNSHeader(43707, flags=expected_flags, qd_count=1, an_count=2, ns_count=1, ar_count=1)
    expected_question = DNSQuestion('example.com', 1, 1)
    expected_answer1 = DNSRecord('example.com', 1, 1, 300, 4, '93.184.216.34')
    expected_answer2 = DNSRecord('example.com', 1, 1, 300, 4, '93.184.216.35')
    expected_authority = DNSRecord(name='example.com', _type=2, _class=1, ttl=86400, rdlength=6, rdata='ns1.example.com')
    expected_additional = DNSRecord(name='ns1.example.com', _type=1, ttl=300, rdlength=4, rdata='10.0.0.1')

    expected = DNSPacket(
        expected_header, 
        questions=[expected_question],
        answers=[expected_answer1, expected_answer2],
        authorities=[expected_authority],
        additionals=[expected_additional]
    )

    assert DNSPacket.from_bytes(buffer) == expected