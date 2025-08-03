# 목표 : 이 코드를 통한 재귀적 리졸버 과정 구현

import socket, struct, secrets, json

def read_root_server_list(path:str):
    # 현재는 임의지정, 추후 루트 서버 선정 알고리즘 수정 예정
    with open(path, 'r') as dns_list:
        root_dns = json.load(dns_list)
    dns_list.close()
    return root_dns['Root-servers'][0]['Ipv4']

def create_req_packet_headers(domain):
    # DNS 리졸빙 요청 패킷 헤더 생성
    
    pass

# 패킷 헤더를 파싱하는 함수
def parser_packet_headers(packet):
    pass

def main():
    # 첫 번째 룩업
    TARGET_URL = 'example.com'
    root_dns = read_root_server_list('../root-dns/dns.json')
    print(f'[0] DNS 루트 서버 주소 (기본값) : {root_dns}')
    
    send_headers = create_req_packet_headers(TARGET_URL)
    pass


if __name__ == "__main__":
    main()