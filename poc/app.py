import socket

def get_ip_from_domain(domain):
  try:
    print('socket response', domain)
    ip_address = socket.gethostbyname(domain)
    return ip_address
  except socket.gaierror as e:
    print(f"Error resolving {domain}: {e}")
    return None

domain_name = "www.example.com"
ip = get_ip_from_domain(domain_name)

if ip:
  print(f"{domain_name}의 IP 주소: {ip}")
