#Omar Shahin and Huzayfa Sabri
#P1

import socket
import struct
import random
import sys

def dns_query(hostname):

    #header
    id = random.randint(0, 65535)
    
    # Flags
    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 1
    RA = 0
    Z = 0
    RCODE = 0
    flags = (QR << 15) | (OPCODE << 11) | (AA << 10) | (TC << 9) | (RD << 8) | (RA << 7) | (Z << 6) | RCODE
    QDCOUNT=1
    ANCOUNT=0
    NSCOUNT=0
    ARCOUNT=0
    
    
    # Pack header
    header = struct.pack("!HHHHHH", id,flags, QDCOUNT, ANCOUNT ,NSCOUNT, ARCOUNT)

    # Pack question
    question = b''
    for part in hostname.split('.'):
        question += struct.pack('B', len(part))
        question += part.encode('utf-8')
    question += b'\x00'  
    question += struct.pack('!HH', 1, 1)  

    message = header + question
    print("Preparing DNS Query...")
    return message

def send_query(message, server='8.8.8.8', port=53, timeout=5, max_retries=3):
    print("Contacting DNS Server...")
    print("Sending DNS Query...")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for attempt in range(max_retries):
            try:
                s.sendto(message, (server, port))
                data, _  = s.recvfrom(4096)
                return data, attempt+1  
            except socket.timeout:
                print(f"Timeout reached. Retrying {attempt+1}/{max_retries}...")
        print(f"Error: No response received after {max_retries} attempts.")
        return None, None 

def parse_dns_response(response):
    header = struct.unpack('!HHHHHH', response[:12])
    (qname, qtype, qclass), question_len = parse_question(response[12:])
    answers_offset = 12 + question_len
    answers = []
    for _ in range(header[3]):
        answer, len_read = parse_answer(response, answers_offset)
        answers_offset += len_read
        answers.append(answer)
    return header, (qname, qtype, qclass), answers

def parse_question(response, offset):
    qname, offset = parse_domain_name(response, offset)
    qtype, qclass = struct.unpack('!HH', response[offset:offset+4])
    return qname, qtype, qclass, offset+4

def parse_answer(response, offset):
    aname, offset = parse_domain_name(response, offset)
    atype, aclass, attl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
    offset += 10
    if atype == 1:  # A record
        adata = socket.inet_ntoa(response[offset:offset+rdlength])
    else:
        adata,  = parse_domain_name(response, offset)
    return aname, atype, aclass, attl, adata,rdlength, offset+rdlength

def parse_domain_name(response, offset):
    labels = []
    while True:
        length = response[offset]
        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack('!H', response[offset:offset+2])[0] & 0x3FFF
            labels.append(parse_domain_name(response, pointer)[0])
            offset += 2
            break
        elif length > 0:
            offset += 1
            labels.append(response[offset:offset+length].decode())
            offset += length
        else:
            offset += 1
            break
    return '.'.join(labels), offset

def parse_dns_response(response):
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    z = (flags >> 4) & 7
    rcode = flags & 0xF

    print(f"header.ID: {id}")
    print(f"header.QR:{qr} \nheader.OPCODE:{opcode}\nheader.AA:{aa}\nheader.TC:{tc}\nheader.RD:{rd}\nheader.RA:{ra}\nheader.Z:{z}\nheader.RCODE:{rcode}")
    print(f"header.QDCOUNT: {qdcount}")
    print(f"header.ANCOUNT: {ancount}")
    print(f"header.NSCOUNT: {nscount}")
    print(f"header.ARCOUNT: {arcount}")
    print()
    offset = 12
    for _ in range(qdcount):
        qname, qtype, qclass, offset = parse_question(response, offset)
        print(f"question.QNAME: {qname}\nquestion.QTYPE: {qtype}\nquestion.QCLASS: {qclass}")

    print()
    # Unpack answers
    for _ in range(ancount):
        aname, atype, aclass, attl, adata, rdlength, offset = parse_answer(response, offset)
        print(f"answer.NAME: {aname}\nanswer.TYPE: {atype}\nanswer.CLASS: {aclass}\nanswer.TTL: {attl}\nanswer.RDLENGTH: {rdlength}\nanswer.RDATA: {adata}")
    

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <hostname>")
        sys.exit(1)

    hostname = sys.argv[1]
    query = dns_query(hostname)
    response, attempt = send_query(query)

    if response:
        print(f"DNS response received (attempt {attempt} of 3)")
        print("Processing DNS response...")
        print("-------------------------------")
        parse_dns_response(response)
    else:
        print("Failed to receive DNS response.")
    