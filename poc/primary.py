# 목표 : 이 코드를 통한 재귀적 리졸버 과정 구현

import socket, struct, secrets, json

def read_root_server_list(path:str):
    # 현재는 임의지정, 추후 루트 서버 선정 알고리즘 수정 예정
    with open(path, 'r') as dns_list:
        root_dns = json.load(dns_list)
    dns_list.close()
    return root_dns['Root-servers'][0]['Ipv4']

def create_req_packet(domain:str):
    transecID = secrets.randbits(16)
    # DNS 리졸빙 요청 패킷 헤더 생성
    headers_section = {
        # transecID는 2Bytes == 16bit
        'Transaction ID' : transecID,
        'Flags': 0x0000,
        # 모든 값이 루트 질의 NS로 0적용
        'QDCOUNT': 1,
        'ANCOUNT': 0,
        'NSCOUNT': 0,
        'ARCOUNT': 0,
    }
    
    header_pack = struct.pack('!HHHHHH', \
        headers_section['Transaction ID'],
        headers_section['Flags'],
        headers_section['QDCOUNT'],
        headers_section['ANCOUNT'],
        headers_section['NSCOUNT'],
        headers_section['ARCOUNT'])
    
    Question_section = {
        'QNAME': domain,
        'QTYPE': 1,
        # A  레코드 조회
        'QCLASS': 1
    }
    # Qname 처리
    qname_bytes = b''
    for domain in str(Question_section['QNAME']).split('.'):
        if not domain:
            continue
        qname_bytes += struct.pack('!B', len(domain))
        qname_bytes += domain.encode('ascii')
    qname_bytes += b'\x00'
    
    # QS 섹션 패킹
    qs_pack = struct.pack('!HH', 
        Question_section['QTYPE'],
        Question_section['QCLASS'])
    
    return (header_pack + qname_bytes + qs_pack), transecID

def send_and_recv_packet(packets: dict, domain:str):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_sent = client_socket.sendto(packets, (domain, 53))
    response_data, _ = client_socket.recvfrom(4096)
    
    return response_data

# 패킷 헤더를 파싱하는 함수
def parser_packet_headers(packet):
    pass

def main():
    # 첫 번째 룩업
    TARGET_URL = 'example.com'
    root_dns = read_root_server_list('../root-dns/dns.json')
    print(f'[0] DNS 루트 서버 주소 (기본값) : {root_dns}')
    
    send_headers, transecID = create_req_packet(TARGET_URL)
    print(f'[1] 생성된 RAW 패킷 데이터 : {send_headers}\n[2] Receive TransecID : {transecID}')
    
    data = send_and_recv_packet(send_headers, root_dns)
    print(f'[3] 수신된 데이터 {data}')

if __name__ == "__main__":
    main()