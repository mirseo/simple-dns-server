# 목표 : 이 코드에서는 실제로 DNS요청을 보내는 걸 목적으로 합니다.

import socket, struct, json, secrets

def main():
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
            # 업스트림 (쿼리 0, 질의 1)
            'QR' : 0,
            # QPCODE(쿼리 타입)
            'OPCODE': 0,
            'RD' : 0,
            'AA' : 0,
            'TC' : 0,
            'RA' : 0,
            'Z ': 0
        },
        'QDCOUNT': 1,
        'ANCOUNT': 0,
        'NSCOUNT': 0,
        'ARCOUNT': 0,
    }
    print(headers)
    
    
    
    
    pass


if __name__ == "__main__":
    main()