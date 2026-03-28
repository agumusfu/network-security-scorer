import wmi
from scanner.utils import run_command

def check_firewall():
    is_active = False
    try:
        # Netsh ile tüm güvenlik duvarı profillerini tarıyoruz
        out = run_command(["netsh", "advfirewall", "show", "allprofiles"])
        if "state" in out and "on" in out:
            is_active = True
        elif "durum" in out and "açık" in out:
            is_active = True
    except Exception as e:
        return {'status': False, 'error': str(e)}

    return {'status': is_active}

def check_antivirus():
    has_av = False
    details = []
    try:
        # Windows Security Center WMI sınıfından AV bilgisini çekiyoruz
        c = wmi.WMI(namespace="root\\SecurityCenter2")
        antiviruses = c.AntivirusProduct()
        for av in antiviruses:
            details.append(av.displayName)
            has_av = True
    except Exception:
        try:
            # WMI de patlarsa alternatif olarak powershell devreye giriyor
            out = run_command(["powershell", "-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled"])
            if "true" in out:
                 has_av = True
                 details.append("Windows Defender (PowerShell)")
        except:
             return {'status': False, 'error': "Failed to resolve AV"}

    return {'status': has_av, 'details': details}

def check_guest_account():
    is_active = False
    try:
        # Sistemi yoklayıp guest hesabı inaktif mi diye net user ile bakıyoruz
        out = run_command(["net", "user", "Guest"])
        if "yes" in out or "evet" in out:
            for line in out.splitlines():
                if ("account active" in line and "yes" in line) or ("hesap etkin" in line and "evet" in line):
                    is_active = True
                    break
    except Exception as e:
         return {'status': None, 'error': str(e)}
         
    return {'status': is_active}

def check_password_policy():
    policy = {
        'min_length': 0,
        'max_age': 0
    }
    try:
        # Mevcut şifre zorunlulukları neler onu listeliyoruz
        out = run_command(["net", "accounts"])
        for line in out.splitlines():
            if "minimum password length" in line or "parola uzunluğu" in line:
                parts = line.split()
                if parts and parts[-1].isdigit():
                    policy['min_length'] = int(parts[-1])
            elif "maximum password age (days)" in line or "parola geçerlilik süresi (gün)" in line:
                parts = line.split()
                if parts and parts[-1].isdigit():
                    policy['max_age'] = int(parts[-1])
                    
    except Exception as e:
         return {'status': False, 'error': str(e)}
         
    return {'status': True, 'policy': policy}
