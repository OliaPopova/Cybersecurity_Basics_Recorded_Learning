import nmap

def scan(target):
    nm = nmap.PortScanner()
    print(f"Scanning target: {target}")
    
    try:
        # Проводим сканирование на открытые порты
        nm.scan(target, '22-1024')  # Сканирование портов с 22 по 1024
        print("Scan info: ", nm.all_hosts())
        
        for host in nm.all_hosts():
            print(f"Host: {host}")
            print(f"Host state: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = nm[host][proto].keys()
                for port in lport:
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
    
    except Exception as e:
        print(f"Error: {e}")

# Ввод адреса для сканирования
target_ip = input("Enter the target IP to scan: ")
scan(target_ip)
