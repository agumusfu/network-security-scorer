# AGENTS.md

## Uyulması Gereken Zorunlu Kurallar
- Tüm testler ve çalıştırma işlemleri KESİNLİKLE **Yönetici (Administrator)** yetkisine sahip bir Windows terminalinde yapılmalıdır. Aksi takdirde WMI ve Kayıt Defteri (`winreg`) sorguları yetkilendirme nedeniyle eksik veya hatalı dönecektir.
- Proje yalnızca Windows sistemler için tasarlanmıştır. POSIX/Linux tabanlı dizin yolları veya API'ler önermeyin/eklemeyin.
- Windows işletim sistemi araçlarını (`netsh`, `sc`, `powershell`, `net`) çağırırken KESİNLİKLE doğrudan `subprocess.run` kullanmayın. Yerel Windows dil setlerinden (`cp1254`) kaynaklanan `UnicodeDecodeError` sorunlarını aşmak için mecburi olarak `scanner.utils.run_command(cmd_list)` yardımcı fonksiyonunu kullanın.

## Depoya Özgü Standartlar (Conventions)
- Tüm tarayıcı modülleri `main.py` içerisinde `ThreadPoolExecutor` kullanılarak eşzamanlı (paralel) çalıştırılmaktadır. Eklenecek tüm yeni tarayıcı fonksiyonlar "thread-safe" olmalıdır.
- WMI (Windows Management Instrumentation) sorguları dahil edileceğinde, COM (Component Object Model) arayüzünde çoklu-iş parçacığı (cross-thread) çakışmasını önlemek için `wmi.WMI()` nesnesini dosya/global düzeyde değil, fonksiyon bloğu içinde yerel (local) olarak tanımlayın.
- Terminal çıktısı içeren eklentiler her zaman projenin görsel stiline uyumlu olması adına (`reporter/report.py` dosyasındaki standartlara) bağlı kalmalı ve `colorama` modülünün değişkenleriyle renkli tasarlanmalıdır.

## İşlemi Tamamlamadan Önce Doğrulama
- Eklenen yeni 3. taraf paketlerin mutlak suretle Windows uyumlu olduğundan emin olun ve `requirements.txt` dosyasına kalıcı olarak ekleyin.
- Herhangi bir değişikliği sonlandırmadan önce, yetkili (Administrator) bir terminal üzerinden `python main.py` çalıştırarak asenkron (eşzamanlı) kodda bir karakter kodlama (charmap) hatası, takılma veya yetki döngüsü oluşmadığını kontrol edin.
