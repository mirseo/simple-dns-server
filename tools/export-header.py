import socket

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
        
        headers = data.split(b'\n')
        
        print(headers)
        
        print(f"Received {len(data)} bytes from {address}")

if __name__ == "__main__":
    main()