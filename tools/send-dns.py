# 목표 : 이 코드에서는 실제로 DNS요청을 보내는 걸 목적으로 합니다.

import socket, struct, json, secrets

def main():
    TARGET_DOMAIN = 'example.com'
    # root dns 조회
    with open('../root-dns/dns.json', 'r') as dns_list:
        root_dns = json.load(dns_list)
        
    dns_list.close()
    # 임의로 A DNS 서버 지정 - To-do : 루트  DNS 서버 선정 알고리즘 구현 (PUBLIC IP 기반)
    # Update > URL > IP변경
    root_dns_server_url = root_dns['Root-servers'][0]['Ipv4']
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
        'QTYPE': 1,
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
        qname_parts = []
        reading_point = offset
        # 현재 바이트
        
        # 오프셋 업데이트 바이트
        bytes_consumed_for_this_name = 0
        
        def decode_dns_name(data_bytes, offset_start):
            name_parts = []
            current_reading_offset = offset_start # 현재 바이트를 읽는 위치
            bytes_consumed_for_this_name = 0 # 이 이름 파싱에 사용된 총 바이트 수 (offset 업데이트용)

            while True:
                # 버그 수정(시도) : UnicodeDecodeError: 'ascii' codec can't decode byte 0xc0 in position 12: ordinal not in range(128)
                # 데이터 검사 추가
                if current_reading_offset >= len(data_bytes):
                    print(f'데이터 읽기 실패 : {current_reading_offset}')
                    # 데이터 끝 도착 리딩 중단
                    break
                
                length_or_pointer_byte = data_bytes[current_reading_offset]
                
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

            return '.'.join(name_parts), bytes_consumed_for_this_name
        
        # print('decoded dns', decode_dns_name(data, 12))
        
        records = {}
        
        # RR 구조
        # NAME : 가변 : 도메인 이름
        # TYPE : 2 : 레코드 타입 A=1, NS=2, CNAME=5
        # CLASS : 2 : CLASS(INET : IN)
        # TTL : 4 : Cache
        # RDL : 2 : Field길이
        # RDATA : RDL : 실제 레코드 데이터
        
        # RDATA 해석
        print('rr section offset', offset)
        name, cd_bytes = decode_dns_name(data, offset)
        
        records['Name'] = name,
        # 오프셋 이동
        offset += cd_bytes
        
        print('mved offset', offset)
        
        # 아하하.... 패킷 순서가 잘못되었었네요... 어쨋든 해결했으니 Ok!
        Question_section = struct.unpack('!HH', data[offset:offset+4])
        print ('Question section:', {
            'QTYPE': Question_section[0],
            'QCLASS': Question_section[1]
        })
        offset += 4
        print('Question section offset', offset)
        
        # type, class, ttl, rdlength 2,2,4,2 (bytes)
        
        records['TYPE'], records['CLASS'], records['TTL'], records['RDLENGTH'] = \
            struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        
        # print('records temp', records)
        
        # RDATA 구성 ! 거의 다 왔다! ☆
        
        # 다음 오프셋으로 이동해서 데이터 불러오기
        raw_rdata = data[offset:offset + records['RDLENGTH']]
        records['RDATA_RAW'] = raw_rdata        
        
        # A record <- 일반 레코드로 해석하기 위해 단줄 if 풀기
        if records['TYPE'] == 1:
            if records['RDLENGTH'] == 4:
                records['RDATA'] = socket.inet_ntoa(raw_rdata)
            else:
                records['RDATA'] = f'Malformed A Record RDATA:{raw_rdata.hex()}'
        # records['RDATA'] = socket.inet_ntoa(raw_rdata) if (records['TYPE'] == 1 and records['RDLENGTH'] == 4) else f'Malformed A Record RDATA:{raw_rdata.hex()}'
        
        # NS record
        # 여기서는 압축될 수 있으니까 FUNC에서 전체 바이트 응답
        elif records['TYPE'] == 2:
            ns_name, _ = decode_dns_name(data, offset)
            records['RDATA'] = ns_name      
        
        # AAAA
        elif records['TYPE'] == 28:
            if records['RDLENGTH'] == 16:
                records['RDATA'] = socket.inet_ntop(socket.AF_INET6, data)    
            else:
                records['RDATA'] = f'Malformed A Record RDATA:{raw_rdata.hex()}'
        
        # PTR
        # PTR 은 IP > DNS 이니까, DNS NAME = A 레코드와 동일 (단 한번 더 처리함)
        elif records['TYPE'] == 12:
            ns_name_ptr, _ = decode_dns_name(data, offset)
            records['RDATA'] = ns_name_ptr 
            
        # 모르는 레코드
        else:
            # 모르는 거니까 일단 h16 데이터 넣기
            records['RDATA'] = data.hex()
            
        offset += records['RDLENGTH']
        
        print('records temp', records)
        
        

    else:
        print('Data too short for DNS header')
    print(offset)

    print(f"Received {len(data)} bytes from {server_address}")
    
    pass


if __name__ == "__main__":
    main()