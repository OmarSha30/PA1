import socket
import struct
import threading
import random
import sys
import time

def dns_query(hostname):

    # Validate the hostname format and length
    if not 1 < len(hostname) <= 253 or ".." in hostname or hostname[-1] == '.' or hostname[0] == '.':
        raise ValueError("Invalid hostname format")

    labels = hostname.split('.')
    for label in labels:
        if not 1 <= len(label) <= 63:
            raise ValueError(f"Invalid label '{label}' in hostname")

    #header
    id=random.randint(0, 65535)
    qr=0
    opcode=0
    aa=0
    tc=0
    rd=1
    ra=0
    z=0
    rcode=0
    qdcount=1
    ancount=0
    nscount=0
    arcount=0

    flags = (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) | (ra << 7) | (z << 4) | rcode
    header = struct.pack("!6H", id, flags, qdcount, ancount, nscount, arcount)

    #question 
    qname_parts = []
    for i in hostname.split('.'):
        qname_parts.append(bytes([len(i)]) + i.encode())
    
    qname_parts.append(b'\x00')
    qname = b''.join(qname_parts)

    qtype = b'\x00\x01'
    qclass = b'\x00\x01'

    question = qname + qtype + qclass

    # Concatenate header and question to form the complete DNS message
    dns_message = header + question

    # Convert the binary DNS message to a hexadecimal representation
    hex_message = dns_message.hex()

    # Return the cleaned hexadecimal message
    return hex_message.replace(" ", "").replace("\n", "")

#print(dns_query("gmu.edu"))

def send_query(dns_query, dns_ip, dns_port=53, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    dns_query = bytes.fromhex(dns_query)
    try:
        sock.sendto(dns_query, (dns_ip, dns_port))
        print("Connection Successful....")
        print(dns_query)
        return sock
    except socket.timeout:
        print("Timeout: DNS query timed out")
        sock.close()
        return None

def receive_response(sock):
    try:
        data, addr = sock.recvfrom(1024)  # receive up to 1024 bytes
        print("Received response from:", addr)

        # Unpack the header
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!6H', data[:12])

        # Parse flags
        qr = (flags & 0x8000) >> 15
        opcode = (flags & 0x7800) >> 11
        aa = (flags & 0x0400) >> 10
        tc = (flags & 0x0200) >> 9
        rd = (flags & 0x0100) >> 8
        ra = (flags & 0x0080) >> 7
        z = (flags & 0x0070) >> 4
        rcode = flags & 0x000F

        print("ID:", id)
        print("QR:", qr)
        print("OPCODE:", opcode)
        print("AA:", aa)
        print("TC:", tc)
        print("RD:", rd)
        print("RA:", ra)
        print("Z:", z)
        print("RCODE:", rcode)
        print("QDCOUNT:", qdcount)
        print("ANCOUNT:", ancount)
        print("NSCOUNT:", nscount)
        print("ARCOUNT:", arcount)

        # Parsing the question section
        offset = 12  # past the header
        for _ in range(qdcount):
            qname, offset = parse_qname(data, offset)
            qtype, qclass = struct.unpack('!2H', data[offset:offset + 4])
            offset += 4
            print("QNAME:", qname)
            print("QTYPE:", qtype)
            print("QCLASS:", qclass)

        # Parsing the answer section
        for _ in range(ancount):
            name, offset = parse_qname(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack('!2HlH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength

            print("NAME:", name)
            print("TYPE:", rtype)
            print("CLASS:", rclass)
            print("TTL:", ttl)
            if rtype == 1:  # A record
                print("IP:", socket.inet_ntoa(rdata))

    except socket.timeout:
        print("Timeout: No response received")

def parse_qname(data, offset):
    labels = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode())
        offset += length
    return ".".join(labels), offset

def main(): 
    
    # if(len!=2):
    #     print("Error: not enough args !!")
    #     sys.exit(1)

    google_ip = "8.8.8.8"
    hostname = sys.argv[1]
    query = dns_query(hostname)
    sock = send_query(query, google_ip, dns_port=53, timeout=5)
    if sock:
        receive_response(sock)
        sock.close()

if __name__=="__main__":
    main()