import config
from colorama import Fore, Style

def print_report(score, deductions, findings):
    en = config.LANG == 'EN'
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*60}")
    print(f"{Fore.CYAN}{Style.BRIGHT}     " + ("NETWORK SECURITY ANALYSIS REPORT" if en else "   AĞ GÜVENLİĞİ ANALİZ RAPORU"))
    print(f"{Fore.CYAN}{Style.BRIGHT}{'='*60}\n{Style.RESET_ALL}")
    
    # Skora göre renk ve seviye belirleme
    if score >= 90:
        level_color = Fore.GREEN
        level_text = "SECURE" if en else "GÜVENLİ"
    elif score >= 70:
        level_color = Fore.YELLOW
        level_text = "ACCEPTABLE" if en else "KABUL EDİLEBİLİR"
    elif score >= 50:
        level_color = Fore.LIGHTRED_EX
        level_text = "WEAK" if en else "ZAYIF"
    else:
        level_color = Fore.RED + Style.BRIGHT
        level_text = "CRITICAL" if en else "KRİTİK"

    print(f"{Style.BRIGHT}" + ("OVERALL SECURITY SCORE" if en else "GENEL GÜVENLİK SKORU") + f": {level_color}{score} / 100 ({level_text}){Style.RESET_ALL}\n")

    # Negatif puan tablosu ve bulgular listeleniyor
    print(f"{Fore.MAGENTA}{Style.BRIGHT}--- " + ("Vulnerabilities and Point Deductions" if en else "Tespit Edilen Zafiyetler ve Puan Kesintileri") + f" ---{Style.RESET_ALL}")
    if not deductions:
         msg = "No critical vulnerabilities or risks identified. Congratulations!" if en else "Hiçbir kritik güvenlik açığı veya risk bulunamadı. Tebrikler!"
         print(f"{Fore.GREEN} [+]{Style.RESET_ALL} {msg}")
    else:
         for d in deductions:
              print(f"{Fore.RED} [!] {d}{Style.RESET_ALL}")
    
    print()
    print(f"{Fore.BLUE}{Style.BRIGHT}--- " + ("Detailed Scan Summary" if en else "Taramaların Detaylı Özeti") + f" ---{Style.RESET_ALL}")
    
    # Port tarama özeti
    print(f"{Style.BRIGHT}[" + ("Network Ports" if en else "Ağ Portları") + f"]{Style.RESET_ALL}")
    for port, info in findings.get('ports', {}).items():
         if info.get('is_open'):
              msg = "OPEN" if en else "AÇIK"
              print(f"  {Fore.RED}[!] Port {port} ({info.get('service')}): {msg}{Style.RESET_ALL}")
         else:
              msg = "CLOSED" if en else "KAPALI"
              print(f"  {Fore.GREEN}[+] Port {port} ({info.get('service')}): {msg}{Style.RESET_ALL}")
              
    # Güvenlik korumaları tablosu
    print(f"\n{Style.BRIGHT}[" + ("System Protections" if en else "Sistem Korumaları") + f"]{Style.RESET_ALL}")
    sys_f = findings.get('system', {})
    
    fw_stat = sys_f.get('firewall', {}).get('status')
    status_fw = ("ON" if en else "AÇIK") if fw_stat else ("OFF" if en else "KAPALI")
    color_fw = Fore.GREEN if fw_stat else Fore.RED
    icon_fw = "[+]" if fw_stat else "[!]"
    print(f"  {color_fw}{icon_fw} Windows Firewall: {status_fw}{Style.RESET_ALL}")
    
    av_stat = sys_f.get('antivirus', {}).get('status')
    status_av = ("DETECTED" if en else "BULUNDU") if av_stat else ("NOT FOUND" if en else "BULUNAMADI")
    color_av = Fore.GREEN if av_stat else Fore.RED
    icon_av = "[+]" if av_stat else "[!]"
    print(f"  {color_av}{icon_av} Antivirus / Defender: {status_av}{Style.RESET_ALL}")
    if sys_f.get('antivirus', {}).get('details'):
         details = ', '.join(sys_f['antivirus']['details'])
         print(f"      (" + ("Registered" if en else "Tanınanlar") + f": {details})")
         
    # Protokoller tablosu
    print(f"\n{Style.BRIGHT}[Protokoller / Protocols]{Style.RESET_ALL}")
    protos = findings.get('protocols', {})
    smb_stat = protos.get('smbv1', {}).get('status')
    status_smb = ("ACTIVE (RISKY)" if en else "AKTİF (RİSKLİ)") if smb_stat else ("DISABLED / SECURE" if en else "KAPALI / GÜVENLİ")
    color_smb = Fore.RED if smb_stat else Fore.GREEN
    icon_smb = "[!]" if smb_stat else "[+]"
    print(f"  {color_smb}{icon_smb} SMBv1 " + ("Status" if en else "Durumu") + f": {status_smb}{Style.RESET_ALL}")
    
    telnet_stat = protos.get('telnet', {}).get('status')
    status_tel = ("ACTIVE (RISKY)" if en else "AKTİF (RİSKLİ)") if telnet_stat else ("DISABLED / SECURE" if en else "KAPALI / GÜVENLİ")
    color_tel = Fore.RED if telnet_stat else Fore.GREEN
    icon_tel = "[!]" if telnet_stat else "[+]"
    print(f"  {color_tel}{icon_tel} Telnet " + ("Service" if en else "Servisi") + f": {status_tel}{Style.RESET_ALL}")
    
    # Ağ DNS tablosu
    net = findings.get('network', {})
    print(f"\n{Style.BRIGHT}[" + ("Network Configuration" if en else "Ağ Yapılandırması") + f"]{Style.RESET_ALL}")
    prof = ', '.join(net.get('profile', {}).get('profiles', []))
    print(f"  {Fore.YELLOW}[i] " + ("Connection Profiles" if en else "Bağlantı Profilleri") + f": {prof}{Style.RESET_ALL}")
    
    dns = net.get('dns', {})
    dns_servers = dns.get('servers', [])
    label_dns = "Settings: DNS Servers" if en else "Ayarlı DNS Sunucuları"
    
    if not dns_servers:
        msg = "DNS Not Found" if en else "DNS Bulunamadı"
        print(f"  {Fore.RED}[!] {label_dns}: {msg}{Style.RESET_ALL}")
    else:
        dns_str = ', '.join(dns_servers)
        if dns.get('status'):
            print(f"  {Fore.GREEN}[+] {label_dns}: {dns_str}{Style.RESET_ALL}")
        else:
            warn_msg = "(Warning: DNS found but it may not be a secure DNS)" if en else "(Uyarı: DNS var ama güvenilir bir DNS olmayabilir)"
            print(f"  {Fore.YELLOW}[!] {label_dns}: {dns_str} {warn_msg}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*60}{Style.RESET_ALL}\n")
