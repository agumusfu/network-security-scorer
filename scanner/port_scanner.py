import socket
import concurrent.futures
from colorama import Fore, Style
import config

def check_single_port(target, port, service):
    # Port kontrolü için basit bir socket bağlantısı kuruyoruz
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        if s.connect_ex((target, port)) == 0:
            return port, {'service': service, 'is_open': True}
        else:
            return port, {'service': service, 'is_open': False}
    except Exception as e:
        return port, {'service': service, 'is_open': False, 'error': str(e)}
    finally:
        s.close()

def scan_ports(target='127.0.0.1'):
    # Saldırganların en çok yokladığı kritik portlar
    ports_to_check = { 21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP" }
    results = {}
    en = config.LANG == 'EN'
    
    if en:
        print(f"  [*] Critical port scan initiated on {target}...")
    else:
        print(f"  [*] Hedef {target} üzerinde kritik port taraması başlatıldı...")
    
    # Tarama işlemini hızlandırmak için iş parçacıklarına böldük
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports_to_check)) as executor:
        futures = {executor.submit(check_single_port, target, p, s): p for p, s in ports_to_check.items()}
        for future in concurrent.futures.as_completed(futures):
            port, info = future.result()
            results[port] = info
            
            # Sonuçları ekrana basıyoruz
            if info['is_open']:
                msg = "OPEN" if en else "AÇIK"
                print(f"   {Fore.RED}[!] Port {port} ({info['service']}) {msg}{Style.RESET_ALL}")
            else:
                msg = "CLOSED" if en else "KAPALI"
                print(f"   {Fore.GREEN}[+] Port {port} ({info['service']}) {msg}{Style.RESET_ALL}")
                
    return results
