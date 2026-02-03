import io
import struct

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

    if output_length := len(encoded_bytes) > 255:
        raise ValueError(f'Domain cannot be longer than 255 octects, currently {output_length} octects')
    
    return encoded_bytes

def decode_domain_name(reader: io.BytesIO, depth: int = 0) -> str:
    if depth > 15:
        raise ValueError('Reached maximum recursion depth, likely compression loop')
    
    labels = []
    while True:
        label = reader.read(1)

        if not label or label == b'\x00':
            break

        if (label[0] & 0xC0) == 0xC0: # bit mask using 0xC0 = 11000000
            offset_byte = reader.read(1)
            offset = offset_byte[0]
            current_position = reader.tell()

            reader.seek(offset)
            res = decode_domain_name(reader, depth+1) # recursively call for compression pointers
            reader.seek(current_position)

            labels.append(res)
            break
        else:
            length = label[0]
            result_label = reader.read(length)
            ascii_label = result_label.decode('ascii')
            labels.append(ascii_label)
    return '.'.join(labels)

class DNSHeader:
    ...

class DNSQuestion:
    ...

class DNSRecord:
    ...

class DNSPacket:
    ...

