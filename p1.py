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
    for i in hostname.split():
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

    pass

def send_query(dns_query, dns_ip):
    dns_port=53
    timeout=5

    pass

def recieve_response():
    pass

def main():
    
    if(len!=2):
        print("Error: not enought args !!")
        sys.exit(1)

    google_ip = "8.8.8.8"
    hostname = sys.argv[1]
    query = dns_query(hostname)

if __name__=="__main__":
    main()