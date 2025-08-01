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
            if header[2] > 0:
                for i in range(header[2]):
                    qname_length = data[12:].find(b'\x00') + 1
                    qname = data[12:12 + qname_length]
                    print('QNAME:', qname.decode('utf-8'))
                    data = data[12 + qname_length:]
                else:
                    print('No QNAME found in the data')
                
            Question_section = struct.unpack('!HH', data[12:16])
            print ('Question section:', {
                'QTYPE': Question_section[0],
                'QCLASS': Question_section[1]
            })
        else:
            print('Data too short for DNS header')

        print(f"Received {len(data)} bytes from {address}")

if __name__ == "__main__":
    main()