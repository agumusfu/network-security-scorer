import winreg
from scanner.utils import run_command

def check_smbv1():
    is_enabled = False
    try:
        # Direkt registry üzerinden SMBv1 anahtarını kontrol ediyoruz
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            value, regtype = winreg.QueryValueEx(key, "SMB1")
            
            # Değer 1 ise maalesef açık demektir
            if value == 1:
                is_enabled = True
    except FileNotFoundError:
        # Anahtar yoksa genelde Windows kendi kapatmıştır, sorun yok
        pass
    except PermissionError:
        return {'status': None, 'error': 'Permission Denied.'}
    except Exception as e:
        return {'status': None, 'error': str(e)}
        
    return {'status': is_enabled}

def check_telnet():
    is_running = False
    try:
        # Telnet servisinin çalışıp çalışmadığına bakıyoruz
        out = run_command(["sc", "query", "TlntSvr"])
        
        if "running" in out or "çalişiyor" in out:
            is_running = True
        elif "failed 1060" in out or "hata 1060" in out:
            is_running = False
    except Exception as e:
        return {'status': None, 'error': str(e)}
        
    return {'status': is_running}
