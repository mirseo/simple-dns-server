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
    
    # 트랜젝션 키 생성
    transecID = int(secrets.token_hex(2)[-4:], 16) & 0x6FFF
    print('transec id', transecID)
    
    
    
    
    pass


if __name__ == "__main__":
    main()