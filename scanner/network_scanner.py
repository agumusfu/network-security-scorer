from scanner.utils import run_command
import wmi

def check_network_profile():
    profiles = []
    try:
        # Mevcut ağ profilini (Public, Private vb.) powershell üzerinden çekiyoruz
        out = run_command(["powershell", "-Command", "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"])
        for p in out.splitlines():
             p = p.strip()
             if p:
                  profiles.append(p)
    except Exception as e:
         return {'status': False, 'error': str(e)}

    return {'status': True, 'profiles': profiles}

def check_dns():
    dns_servers = []
    try:
        # En hızlı yöntem olduğu için WMI ile bağdaştırıcıların DNS ayarlarını okuyoruz
        c = wmi.WMI()
        adapters = c.Win32_NetworkAdapterConfiguration(IPEnabled=True)
        for adapter in adapters:
            if adapter.DNSServerSearchOrder:
                for dns in adapter.DNSServerSearchOrder:
                    dns_servers.append(dns)
        
        # Çoklayan IP'leri temizledik
        dns_servers = list(set(dns_servers))
        
    except Exception as e:
        return {'status': False, 'error': str(e)}

    # Bilinen ana akım güvenilir DNS'ler
    trusted_dns = [
        '8.8.8.8', '8.8.4.4',
        '1.1.1.1', '1.0.0.1',
        '208.67.222.222', '208.67.220.220',
        '9.9.9.9', '149.112.112.112',
    ]
    
    is_secure = True
    untrusted = []
    
    for dns in dns_servers:
         # Yerel network IP'lerini (örneğin modem) pas geç
         if dns.startswith("192.168") or dns.startswith("10.") or dns.startswith("172."):
              continue
         
         # Eğer liste dışıysa muhtemelen ISS DNS'idir, güvenli saymıyoruz
         if dns not in trusted_dns:
              untrusted.append(dns)
              is_secure = False
              
    return {'status': is_secure, 'servers': dns_servers, 'untrusted': untrusted}
