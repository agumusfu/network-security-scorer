import sys
import os
import ctypes
import concurrent.futures
from colorama import init, Fore, Style

# Kendi klasörümüzü path'e ekliyoruz ki import hatası olmasın
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

from scanner.port_scanner import scan_ports
from scanner.system_scanner import check_firewall, check_antivirus, check_guest_account, check_password_policy
from scanner.protocol_scanner import check_smbv1, check_telnet
from scanner.network_scanner import check_network_profile, check_dns
from reporter.scorer import calculate_score
from reporter.report import print_report

def is_admin():
    # Komut satırı yönetici haklarıyla mı açılmış ona bakıyoruz
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_system_scans():
    # Sistem kontrollerini topluca çalıştıran fonksiyon
    return {
        'firewall': check_firewall(),
        'antivirus': check_antivirus(),
        'guest_account': check_guest_account(),
        'password_policy': check_password_policy()
    }

def run_protocol_scans():
    # Protokol zafiyetleri için sarmalayıcı (wrapper) call
    return {'smbv1': check_smbv1(), 'telnet': check_telnet()}

def run_network_scans():
    # Profil ve DNS analizini aynı pakete alıyoruz
    return {'profile': check_network_profile(), 'dns': check_dns()}

def main():
    init(autoreset=True)
    
    print(f"{Fore.CYAN}--- Welcome to Network Security Scorer / Ağ Güvenliği Skorer ---{Style.RESET_ALL}")
    lang_choice = input("Please select language / Lütfen dil seçiniz (EN/TR) [Default: EN]: ").strip().upper()
    config.LANG = 'TR' if lang_choice == 'TR' else 'EN'
    en = config.LANG == 'EN'
    
    if en:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Network Security Scorer - Initiating ===")
    else:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Ağ Güvenliği Skorer - Başlatılıyor ===")
    
    # Bazı Windows araçları sadece yetkili açıldığında sonuç döndürür
    if not is_admin():
        if en:
            print(f"\n{Fore.RED}{Style.BRIGHT}[WARNING] The program is NOT running with Administrator privileges!")
            print(f"{Fore.YELLOW}Certain services, WMI, and registry checks may fail or return incomplete results.")
            print(f"{Fore.YELLOW}Please run the terminal as Administrator for maximum accuracy.\n")
            q = f"{Style.RESET_ALL}Do you want to continue anyway? (Y/N): "
        else:
            print(f"\n{Fore.RED}{Style.BRIGHT}[UYARI] Program Yönetici (Administrator) yetkileriyle ÇALIŞMIYOR!")
            print(f"{Fore.YELLOW}Bazı servis, WMI ve kayıt defteri (registry) kontrolleri başarısız olabilir veya eksik sonuç verebilir.")
            print(f"{Fore.YELLOW}En doğru puanlama için lütfen terminali Yönetici olarak çalıştırın.\n")
            q = f"{Style.RESET_ALL}Yine de devam etmek istiyor musunuz? (E/H): "
            
        try:
            response = input(q).lower()
            if response not in ['e', 'evet', 'y', 'yes']:
                sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)
            
    all_findings = {}
    
    if en:
        print(f"\n{Fore.BLUE}[*] Launching all security scans CONCURRENTLY. Please wait...")
    else:
        print(f"\n{Fore.BLUE}[*] Tüm güvenlik taramaları EŞZAMANLI (Paralel) başltılıyor. Lütfen bekleyin...")
    
    # Tarayıcılar bekleme yapmasın diye iş parçacığı havuzu (thread pool) kullanıyoruz 
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_ports = executor.submit(scan_ports, '127.0.0.1')
        future_sys = executor.submit(run_system_scans)
        future_protos = executor.submit(run_protocol_scans)
        future_net = executor.submit(run_network_scans)
        
        all_findings['ports'] = future_ports.result()
        all_findings['system'] = future_sys.result()
        all_findings['protocols'] = future_protos.result()
        all_findings['network'] = future_net.result()
    
    if en:
        print(f"\n{Fore.MAGENTA}[*] Scans completed. Analyzing findings and calculating score...")
    else:
        print(f"\n{Fore.MAGENTA}[*] Taramalar bitti. Bulgular analiz ediliyor ve skor hesaplanıyor...")
        
    # Her şeyi toplayıp son notu kestiriyoruz
    final_score, deductions = calculate_score(all_findings)
    print_report(final_score, deductions, all_findings)

if __name__ == "__main__":
    main()
