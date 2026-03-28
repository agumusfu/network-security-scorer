import config

def calculate_score(findings):
    score = 100
    deductions = []
    en = config.LANG == 'EN'

    # Temel sistem ve hesap kontrolleri
    sys_f = findings.get('system', {})
    if sys_f.get('firewall', {}).get('status') is False:
        score -= 30
        deductions.append("-30: Windows Firewall is disabled." if en else "-30: Windows Güvenlik Duvarı kapalı.")
        
    if sys_f.get('antivirus', {}).get('status') is False:
        score -= 30
        deductions.append("-30: Active Antivirus or Windows Defender could not be found." if en else "-30: Aktif bir Antivirüs veya Windows Defender bulunamadı.")
        
    if sys_f.get('guest_account', {}).get('status') is True:
        score -= 10
        deductions.append("-10: Guest Account is ACTIVE." if en else "-10: Misafir (Guest) hesabı aktif durumda.")
        
    if sys_f.get('password_policy', {}).get('status'):
        pol = sys_f['password_policy'].get('policy', {})
        if pol.get('min_length', 0) < 8:
            score -= 10
            msg = f"-10: Weak Password Policy (Length: {pol.get('min_length')}, Recommended: >=8)." if en else f"-10: Zayıf Parola Politikası (Minimum Uzunluk: {pol.get('min_length')} karakter, tavsiye edilen: >=8)."
            deductions.append(msg)

    # Tehlikeli olabilecek açık portları hesaba katıyoruz
    ports = findings.get('ports', {})
    for port, info in ports.items():
        if info.get('is_open'):
            if port == 445:
                score -= 15
                deductions.append("-15: Critical Port Open (Port 445 - SMB)." if en else "-15: Kritik Port Açık (Port 445 - SMB).")
            elif port == 3389:
                score -= 10
                deductions.append("-10: RDP Port (3389) seems open to the public." if en else "-10: RDP Portu (3389) dışarıya açık durumunda görünüyor.")
            elif port == 23:
                score -= 15
                deductions.append("-15: Unencrypted Telnet (Port 23) is open." if en else "-15: Şifresiz Telnet (Port 23) portu açık.")
            else:
                score -= 5
                deductions.append(f"-5: {info.get('service')} service is exposed (Port {port})." if en else f"-5: {info.get('service')} servisi (Port {port}) açık.")

    # Riskli protokoller
    protos = findings.get('protocols', {})
    if protos.get('smbv1', {}).get('status') is True:
        score -= 20
        deductions.append("-20: SMBv1 protocol is ACTIVE! (Critical vulnerability for ransomware)." if en else "-20: SMBv1 protokolü aktif! (WannaCry vb. fidye yazılımları için kritik zafiyet).")
        
    if protos.get('telnet', {}).get('status') is True:
        score -= 15
        deductions.append("-15: Windows Telnet Service is installed and running." if en else "-15: Windows Telnet servisi kurulu ve çalışıyor (Ağ trafiği şifrelenmez!).")

    # Ağ yapılandırması kontrolleri üzerinden puan kırma
    net_f = findings.get('network', {})
    profil_durumlari = net_f.get('profile', {}).get('profiles', [])
    if 'Public' in [p.capitalize() for p in profil_durumlari]:
        score -= 5
        deductions.append("-5: Network profile is set to 'Public' (Untrusted)." if en else "-5: Sistemin bağlı olduğu ağ profili 'Public' (Ortak Alan) olarak yapılandırılmış.")
        
    if net_f.get('dns', {}).get('status') is False:
        score -= 10
        untrusted = net_f['dns'].get('untrusted', [])
        dns_str = ', '.join(untrusted)
        deductions.append(f"-10: Unrecognized/Untrusted DNS servers in use: {dns_str}" if en else f"-10: Bilinmeyen ve muhtemelen güvensiz DNS sunucuları kullanılıyor: {dns_str}")

    # Skor 0'ın altına inmesin
    if score < 0:
        score = 0
        
    return score, deductions
