# Network Security Scorer

## English
A modular, fully functional Python CLI tool to audit the security posture of local Windows environments. 
It checks for open critical ports, Windows Firewall & Defender status, vulnerable protocols (SMBv1, Telnet), and network DNS configuration in parallel.

### Features
- **Language Selection:** Supports English and Turkish out-of-the-box.
- **Concurrent Scanning:** Uses `ThreadPoolExecutor` to perform network port scans and native system checks simultaneously.
- **Native WMI Integration:** Replaces bloated CLI parsing (like `ipconfig`) with high-speed native Windows Management Instrumentation (WMI) APIs.
- **Scoring Algorithm:** Generates a 0-100 severity score based on the critical level of active risks.
- **Professional Output:** Renders highly readable, color-coded terminal reports via `colorama`.

### Usage
1. Open an **Administrator/Elevated** terminal in Windows.
2. Install dependencies: `pip install -r requirements.txt`
3. Hit start: `python main.py`

---

## Türkçe
Yerel Windows sistemlerinin güvenlik duruşunu denetlemek için yazılmış modüler bir Python CLI tespit aracıdır.
Açık kritik portları, Windows Güvenlik Duvarı'nı, Defender durumunu, zafiyetli protokolleri (SMBv1, Telnet) ve ağ DNS yapılandırmasını eşzamanlı olarak kontrol eder.

### Özellikler
- **Dil Seçeneği:** İngilizce ve Türkçe olarak çift dil arayüzüne (i18n) sahiptir. Başlangıçta sorar.
- **Eşzamanlı (Paralel) Tarama:** Ağ portu taramalarını ve sistem kontrollerini birbirini beklemeden aynı anda başlatmak için multi-threading (`ThreadPoolExecutor`) kullanır.
- **Native WMI Entegrasyonu:** `ipconfig` veya komut satırı çıktısı analiz eden yavaş pratikler yerine doğrudan Windows Management Instrumentation API'lerini sömürür ve sıfır gecikmeyle sonuç verir.
- **Skorlama Algoritması:** Sistemdeki aktif risklerin ciddiyetine göre 0 ile 100 arasında bir siber güvenlik puanlaması hesaplar.

### Kullanım
1. Windows'ta başlat menüsünden **Yönetici (Administrator) olarak çalıştırılmış** bir CMD veya PowerShell açın.
2. Gerekli kütüphaneleri yükleyin: `pip install -r requirements.txt`
3. Aracı başlatın: `python main.py`
