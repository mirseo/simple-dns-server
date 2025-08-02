# 목표 : 이 코드에서는 실제로 DNS요청을 보내는 걸 목적으로 합니다.

import socket, struct, json, secrets

def main():
    TARGET_DOMAIN = 'example.com'
    # root dns 조회
    with open('../root-dns/dns.json', 'r') as dns_list:
        root_dns = json.load(dns_list)
        
    dns_list.close()
    # 임의로 A DNS 서버 지정 - To-do : 루트  DNS 서버 선정 알고리즘 구현 (PUBLIC IP 기반)
    root_dns_server_url = root_dns['Root-servers'][0]['URL']
    # print('root dns : ', root_dns)
    print('root dns server : ', root_dns_server_url)
    
    # 트랜젝션 키 생성 (기존에는 16진수 생성 후 10진수 변환 > randbit 사용으로 변경 (연산 효율성 추구))
    transecID = secrets.randbits(16)
    print('transec id', transecID)
    
    headers = {
        # transecID는 2Bytes == 16bit
        'Transaction ID' : transecID,
        'Flags': {
            (0 << 15) | \
            (0 << 11) | \
            (0 << 10) | \
            (0 << 9)  | \
                # rd count(1 == 재귀요청 시)
            (0 << 8)  | \
            (0 << 7)  | \
            (0 << 4)  | \
            (0 << 0)
        },
        'QDCOUNT': 1,
        'ANCOUNT': 0,
        'NSCOUNT': 0,
        'ARCOUNT': 0,
    }
    Question_section = {
        'QNAME':TARGET_DOMAIN,
        'QTYPE': 0,
        # A  레코드 조회
        'QCLASS': 1
    }
    # 모든 Flags 값이 0인 경우
    combind_flags = 0x0000
    
    # DNS 헤더는 12바이트 (H=2BYTE > Hx6 = 12Byte)
    # print('headers', headers)
    print(
        'send-headers',
        headers['Transaction ID'],
        combind_flags,
        headers['QDCOUNT'],
        headers['ANCOUNT'],
        headers['NSCOUNT'],
        headers['ARCOUNT']
    )
    header_send = struct.pack('!HHHHHH', \
        headers['Transaction ID'],
        combind_flags,
        headers['QDCOUNT'],
        headers['ANCOUNT'],
        headers['NSCOUNT'],
        headers['ARCOUNT'])
    print('packed-header', header_send)
    
    # QNAME 패킹
    qname_bytes = b''
    print(Question_section['QNAME'])
    # 대상 도메인과 TLD 분리
    for domain in str(Question_section['QNAME']).split('.'):
        if not domain:
            continue
        qname_bytes += struct.pack('!B', len(domain))
        qname_bytes += domain.encode('ascii')
    # DNS 패킷 Null Byte 생성
    qname_bytes += b'\x00'
    
    # QS 섹션 패킹
    qs_pack = struct.pack('!HH', 
        Question_section['QTYPE'],
        Question_section['QCLASS'])
    
    print('qname', qname_bytes)
    print('qs_pack', qs_pack)
    
    # 최종 패킷
    last_packet = header_send + qname_bytes + qs_pack
    print(last_packet)
    
    # DNS 포트 지정
    ROOT_PORT = 53
    
    # UDP 포트 생성
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # UDP 패킷 송신 
    bytes_sent = client_socket.sendto(last_packet, (root_dns_server_url, ROOT_PORT))
    
    print('sending bytes...', bytes_sent)
    # 4096 바이트 수신
    response_data, server_address = client_socket.recvfrom(4096)
    print('응답 바이트 ', response_data.hex())
    
    
    data = response_data
    # DNS응답 파싱 (export-header.py 재사용)
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

    print(f"Received {len(data)} bytes from {server_address}")
    
    pass


if __name__ == "__main__":
    main()