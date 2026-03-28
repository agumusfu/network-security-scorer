import subprocess

def run_command(cmd_list):
    # Komut satırını görünmez olarak başlatmak için gerekli ayarlar
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    
    # Komutu çalıştırıp çıktıyı yakalıyoruz, TR karakterleri replace ile hallediyoruz
    result = subprocess.run(
        cmd_list,
        capture_output=True,
        text=True,
        errors='replace',
        startupinfo=startupinfo
    )
    return result.stdout.lower()
