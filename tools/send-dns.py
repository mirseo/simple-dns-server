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
        'QNAME':TARGET_DOMAIN,
        'QTYPE':'A',
        'QCLASS':'0x0001'
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
    
    
    
    
    
    
    
    pass


if __name__ == "__main__":
    main()