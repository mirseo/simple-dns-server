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
                'Questions': header[2],
                'Answers': header[3],
                'Authority': header[4],
                'Additional': header[5]
            })
        else:
            print('Data too short for DNS header')

        print(f"Received {len(data)} bytes from {address}")

if __name__ == "__main__":
    main()