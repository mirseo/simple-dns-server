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

# DNS 디코딩 함수
def decode_dns_name(data_bytes, offset_start):
    name_parts = []
    current_reading_offset = offset_start # 현재 바이트를 읽는 위치
    bytes_consumed_for_this_name = 0 # 이 이름 파싱에 사용된 총 바이트 수 (offset 업데이트용)
    
    # print('debug : ', current_reading_offset, len(data_bytes))

    while True:
        if current_reading_offset >= len(data_bytes):
            print('데이터 읽기 실패')
            break
        
        length_or_pointer_byte = data_bytes[current_reading_offset]
        
        # 압축 포인터 읽기
        if (length_or_pointer_byte & 0xC0) == 0xC0: # 포인터
            pointer_value = struct.unpack('!H', data_bytes[current_reading_offset:current_reading_offset+2])[0]
            actual_offset = pointer_value & 0x3FFF # 하위 14비트 추출
                    
                    # + 버그 수정(2차 시도) offset 업데이트 누락 해결
            current_reading_offset += 2
                    
                    # 포인터가 가리키는 곳에서 이름 파싱 (재귀)
            pointed_name, _ = decode_dns_name(data_bytes, actual_offset) 
            name_parts.append(pointed_name)
                    
            bytes_consumed_for_this_name += 2 # 포인터는 2바이트 소비
            break # 포인터를 만나면 현재 이름 파싱은 끝
                    
        elif length_or_pointer_byte == 0: # 널 바이트 (이름의 끝)
            bytes_consumed_for_this_name += 1 # 널 바이트 자체도 1바이트 소비
                    # 버그 수정(2차) offset 누락 해결
            current_reading_offset += 1
            break # 이름 파싱 끝
                    
        else: # 일반 레이블 길이
            label_length = length_or_pointer_byte
                    
                    # 버그 수정 시도 (2)
            if current_reading_offset + 1 + label_length > len(data_bytes):
                print(f'데이터 바운더리 초과하는 라벨 {current_reading_offset}')
                break
                    
            label_bytes = data_bytes[current_reading_offset + 1 : current_reading_offset + 1 + label_length]
            name_parts.append(label_bytes.decode('ascii'))
                    
            bytes_consumed_for_this_name += (1 + label_length) # 길이 바이트(1) + 레이블 바이트(길이) 소비
            current_reading_offset += (1 + label_length) # 다음 레이블의 시작 위치로 이동

    # 25.08.03 - 버그 수정 return 문 위치 조정
    return '.'.join(name_parts), bytes_consumed_for_this_name
    

# 패킷 헤더를 파싱하는 함수
def parser_packet_headers(packet, current_offset):
    record = {}
    
    def parse_rr_record(data_bytes, start_offset, id):
            # record = {}
            # print('debug : recv', data_bytes)
            name, name_bytes_consumed = decode_dns_name(data_bytes, start_offset)
            current = start_offset + name_bytes_consumed
            
            record_type, record_code, record_ttl, record_rdlength = struct.unpack('!HHIH', packet[current:current + 10])
            current += 10
            # print(
            #     "debug",
            #     'record_type', record_type,
            #     'record_code', record_code,
            #     'record_ttl', record_ttl,
            #     'record_rdlength', record_rdlength,
            #     'current_offset', current
            # )
            
            # 레코드 파싱 구현
            # a레코드
            if record_type == 1:
                record['TYPE'] = 'A'
                if record_rdlength == 4:
                    record['RDATA'] = socket.inet_ntoa(data_bytes)
                else:
                    record['RDATA'] = f'Malformed A Record RDATA:{record_code.hex()}'
                
            # ns record
            elif record_type == 2:
                record['TYPE'] = 'NS'
                ns_name, _ = decode_dns_name(data_bytes, current)
                record['RDATA'] = ns_name      
                print('NS_NAME', ns_name, _)
            
            # AAAA
            elif record_type == 28:
                record['TYPE'] = 'AAAA'
                if record_rdlength == 16:
                    record['RDATA'] = socket.inet_ntop(socket.AF_INET6, data_bytes)    
                else:
                    record['RDATA'] = f'Malformed A Record RDATA:{record_code.hex()}'
            
            # PTR
            # PTR 은 IP > DNS 이니까, DNS NAME = A 레코드와 동일 (단 한번 더 처리함)
            elif record_type == 12:
                record['TYPE'] = 'PTR'
                ns_name_ptr, _ = decode_dns_name(data_bytes, current)
                record['RDATA'] = ns_name_ptr 
                
            # 모르는 레코드
            else:
                # 모르는 거니까 일단 h16 데이터 넣기
                record['RDATA'] = data_bytes.hex()
                
            current += record_rdlength
            
            
            # print('rr offset', current)
            # print(f'[{id}] parsed_record', record)
            
            return current, record
    # 헤더 분리
    headers = struct.unpack('!HHHHHH', packet[:12])
    current_offset += 12 
    # 패킷 (12바이트 해석 이후이므로 오프셋 12로 업데이트)
    # 주석용 헤더 (ID - 0 , flags - 1, qdcount - 2, answers - 3, authority - 4, additonal - 5)
    
    # RR 구조
    # NAME : 가변 : 도메인 이름
    # TYPE : 2 : 레코드 타입 A=1, NS=2, CNAME=5
    # CLASS : 2 : CLASS(INET : IN)
    # TTL : 4 : Cache
    # RDL : 2 : Field길이
    # RDATA : RDL : 실제 레코드 데이터
        
    # RDATA 해석
    record['Name'], move_bytes = decode_dns_name(packet, current_offset)
    current_offset += move_bytes
    
    Question_section = struct.unpack('!HH', packet[current_offset:current_offset+4])
    current_offset += 4
    
    dns_list, id, stop_chain = [], 0, False
    for i in range(headers[4]):
        id += 1
        current_offset, record = parse_rr_record(packet, current_offset, id)
        # print('returned record', record)
        
        # 25.08.03 - 딕셔너리 메모리 주소 업데이트 버그 수정
        dns_list.append(record.copy())
        # print('now data_list_saved', dns_list)
            # print('totalND', dns_list)
            
            # 스탑체인 리피터 구현 ( A레코드 찾으면 True로 전환 )
        stop_chain = True if record['TYPE'] == 'A' else False
        # print('total_record', dns_list)
    
    # print('NX', record)
    print('[4] 현재 파싱된 레코드 : ', dns_list)
    
    # 레코드에 A 레코드가 있는지 확인 or AAAA
    
    output_records, next_upstream_url = [], []
    for dns in dns_list:
        # print(dns)
        if(dns['TYPE'] == ('A' or 'AAAA')):
            output_records.append(dns.copy())
            print('A레코드를 찾았습니다.')
        elif (dns['TYPE'] == ('NS' or 'CNAME')):
            next_upstream_url.append(dns.copy())
            # 다음 레코드 질의 시작
        else:
            print('해당 도메인은 추적할 수 없습니다. 레코드가 정상적인지 확인해주세요.')
    print('next_upstream', next_upstream_url)
    # print('레코드 추적이 완료되지 않았습니다. 2차 추적을 실시합니다.')
    if not output_records:
        rec = {}
        target_url = dns['Name']
        print(f'2차 추적 개시 ... 목표 DNS : {target_url}')
        
        offset = 0
        
        headers, transecID = create_req_packet(target_url)
        print('다음 리졸브 서버', next_upstream_url[-1]['RDATA'])
        resv_data = send_and_recv_packet(headers, next_upstream_url[-1]['RDATA'])
        offset += 12
        # 헤더 파싱
        # print(decode_dns_name(resv_data, 12))
        
        rec['Name'], move_bytes = decode_dns_name(packet, offset)
        offset += move_bytes
        
        Question_section = struct.unpack('!HH', packet[offset:offset+4])
        offset += 4
        dns_list, id, stop_chain = [], 0, False
        while True:
            id += 1
            offset, record = parse_rr_record(packet, offset, id)
            print('returned record', record)
            
            # 25.08.03 - 딕셔너리 메모리 주소 업데이트 버그 수정
            dns_list.append(record.copy())
            print('now data_list_saved', dns_list)
                # print('totalND', dns_list)
                
                # 스탑체인 리피터 구현 ( A레코드 찾으면 True로 전환 )
            if(dns_list['TYPE'] == ('A' or 'AAAA')):
                pass
            # print('total_record', dns_list)
        
        # print('NX', record)
        print('[4] 현재 파싱된 레코드 : ', dns_list)
        
        print('recv', resv_data)
        print('rec', rec)
    else:
        return output_records
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
    
    current_offset = 0
    # 파싱을 시작하기 전이므로 offset 0 
    
    parsed = parser_packet_headers(data, current_offset)
    print('parser', parsed)
    
    

if __name__ == "__main__":
    main()