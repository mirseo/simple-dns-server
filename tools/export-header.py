import socket, struct

Port = 8124

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ('0.0.0.0', Port)
    try:
        sock.bind(server_addr)
        
    except socket.error as e:
        print(f"Error binding to {server_addr}: {e}")
        return
    
    while True:
        print("\nWaiting to receive message...")
        data, address = sock.recvfrom(512)
        print('data', data)
        


        if len(data) >= 12:
            # !H <- H하나가 각 2Byte이므로 헤더에서 추출 시 12Byte를 DNS헤더가 사용하기 때문에 H6개 필요
            header = struct.unpack('!HHHHHH', data[:12])
            print('header', header)
            print('decoded DNS header:', {
                'ID': header[0],
                'Flags': header[1], 
                'QDCOUNT': header[2],
                'Answers': header[3],
                'Authority': header[4],
                'Additional': header[5]
            })
            # qd Count 기반 가변 도메인 쿼리 처리
            offset = 12
            qname_raw = b''
            if header[2] > 0:
                qname_length = data[offset:].find(b'\x00') + 1
                qname_raw = data[offset:offset + qname_length]
                
                # Parse QNAME (skip length-prefixed format for simplicity)
                qname_parts = []
                i = 0
                while i < len(qname_raw) - 1:  # -1 to skip null terminator
                    length = qname_raw[i]
                    if length == 0:
                        break
                    qname_parts.append(qname_raw[i+1:i+1+length].decode('utf-8'))
                    i += length + 1
                
                qname_str = '.'.join(qname_parts)
                print('QNAME:', qname_str)
                offset += qname_length
            else:
                print('No QNAME found in the data')
                
            Question_section = struct.unpack('!HH', data[offset:offset+4])
            print ('Question section:', {
                'QTYPE': Question_section[0],
                'QCLASS': Question_section[1]
            })
        else:
            print('Data too short for DNS header')

        print(f"Received {len(data)} bytes from {address}")
        
        # Response
        client_ID = header[0]
        QR = 1
        Opcode = 0
        AA = 0
        TC = 0
        RD = 1
        Z = 0
        RA = 1
        CD = 0
        RCODE = 0
        QDCOUNT = header[2]
        ANCOUNT = 1
        NSCOUNT = 0
        ARCOUNT = 0
        
        # Answer section - use pointer to original question name
        RR_NAME = b'\xc0\x0c'  # Pointer to offset 12 (original QNAME)
        RR_TYPE = 1  # A record type
        RR_CLASS = 1
        RR_TTL = 3600
        RR_RDLENGTH = 4
        RR_RDATA = socket.inet_aton('127.0.0.1')
        
        response_header = struct.pack('!HHHHHH', 
            client_ID, 
            (QR << 15) | (Opcode << 11) | (AA << 10) | (TC << 9) | (RD << 8) | (Z << 7) | (RA << 6) | (CD << 5) | RCODE, 
            QDCOUNT, 
            ANCOUNT, 
            NSCOUNT, 
            ARCOUNT
        )
        
        # Include original question section
        question_end = offset + 4
        question_section = data[12:question_end]
        
        answer = RR_NAME + struct.pack('!HHIH', 
            RR_TYPE, 
            RR_CLASS, 
            RR_TTL, 
            RR_RDLENGTH
        ) + RR_RDATA
        
        response = response_header + question_section + answer

        sock.sendto(response, address)
        print(f"Sent response to {address}")

if __name__ == "__main__":
    main()