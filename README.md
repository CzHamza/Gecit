# Geçit

Discord'a giremez oldum bir gün. GoodbyeDPI kullanıyordum o zamana kadar ama bir noktadan sonra güvenemedim ona, ne zaman çalışıp ne zaman çalışmayacağı belli değildi. Oturdum, kendim yazdım bunu.

Geçit küçük bir Python programı. Senin bilgisayarında çalışıyor; sunucu yok, VPN değil, kimseye para ödemiyorsun. Türkiye'de erişim engeli olan sitelere (Discord, Roblox, Wattpad gibi) girmeni sağlıyor.

> Sadece Türk Telekom'da, Windows 11'de denedim. Başka operatörde farklı davranabilir filtre, aşağıdaki `--test` komutuyla kontrol edebilirsin.

## Nasıl çalışıyor

İki katmanlı engel var aslında.

**1. DNS.** `discord.com`'un adresini sorunca operatör yanlış adres veriyor, engel sayfasınınkini (`195.175.254.2`). Geçit adresleri şifreli DNS ile (DoH) soruyor, o yüzden doğru cevabı alıyor.

**2. SNI.** Doğru adrese bağlansan bile bağlantının en başında, TLS el sıkışmasında sitenin adı açık gidiyor. Filtre bunu okuyup kesiyor bağlantıyı. Geçit bu ilk paketi (ClientHello) iki TLS kaydına bölüyor, site adının tam ortasından. Filtre adı bir bütün olarak göremiyor; sunucu ise iki parçayı birleştirip normal devam ediyor.

Bir şey daha öğrendim bu arada: paketi TCP seviyesinde bölmek işe yaramıyor Türk Telekom'da, filtre parçaları birleştirip okuyabiliyor. TLS kaydı seviyesinde bölmek gerekiyor.

Tarayıcılar ve Discord, Windows'un proxy ayarı üzerinden geçiyor Geçit'ten. Ayrıca birşey ayarlamana gerek yok.

## Discord'un güncelleyicisi meselesi

En çok uğraştıran kısım bu oldu. Discord açılırken güncelleme kontrolü yapıyor ama bu kontrolü yapan parça hem Windows'un proxy ayarını takmıyor hem de sadece TLS 1.2 kullanıyor. TLS 1.2'de sunucunun sertifikası şifresiz gidiyor ve içinde `discord.com` yazıyor; filtre de bunu görüp bağlantıyı sessizce boğuyor. Sonuç: Discord açılış ekranında "güncellemeler denetleniyor" deyip kalıyor.

Şöyle çözdüm:

- `hosts` dosyasına tek satır ekleniyor: `127.0.0.1 updates.discord.com`. Güncelleyici Geçit'e geliyor böylece.
- Geçit bu bağlantıyı bilgisayarda kendisi karşılıyor, sunucuya ise TLS 1.3 ile bağlanıyor. TLS 1.3'te sertifika şifreli, filtre göremiyor.
- Bunun için Windows'a bir sertifika yüklemek gerekiyor. Açık olayım: bu, Geçit'in `updates.discord.com` trafiğini görebilmesi demek. O yüzden sertifikayı olabildiğince dar tuttum:
  - **Sadece `updates.discord.com` için geçerli.** İçinde ad kısıtı (name constraints) var, Windows başka hiçbir site için kabul etmiyor.
  - **İmzalayan anahtar hiç kaydedilmiyor.** Sertifika üretilir üretilmez atılıyor, yani kimse (ben dahil) bununla yeni bir sertifika imzalayamıyor.
  - Dosyalar senin bilgisayarında `sertifika/` klasöründe duruyor, hiçbir yere gönderilmiyor.

İstemezsen kurulumu yapma. Tarayıcıda her şey yine çalışır, sadece Discord'un masaüstü uygulaması açılışta takılır (tarayıcıdan discord.com/app ile girebilirsin o zaman).

## Kurulum

Lazım olanlar: Windows 10 ya da 11 ve [Python 3.11 veya üstü](https://www.python.org/downloads/). Python'ı kurarken "Add python.exe to PATH" kutusunu işaretlemeyi unutma.

1. Bu repoyu indir (Code → Download ZIP) ve bir klasöre çıkar.
2. O klasörde bir terminal aç, sertifikayı üretmek için gereken paketi kur:
   ```
   python -m pip install cryptography
   ```
3. Kurulumu çalıştır:
   ```
   python gecit.py --install
   ```
   Önce sertifika için bir pencere açılacak, "Evet" de. Sonra `hosts` dosyası için yönetici izni isteyecek.
4. `Gecit.bat`'a çift tıkla. Bundan sonra Windows açılınca kendisi başlıyor, küçültülmüş bir pencerede.

GoodbyeDPI yada benzeri bir şey açıksa önce onu kapat, ikisi aynı anda çalışmasın.

## Kullanım

Pencere açık olduğu sürece çalışıyor. Kapatınca Windows'un proxy ayarı eski haline dönüyor.

| Komut | Ne yapar |
|---|---|
| `python gecit.py` | Başlatır (`Gecit.bat` da bunu yapıyor) |
| `python gecit.py --test` | Discord ve birkaç engelli sitede hangi yöntemin işe yaradığını gösterir |
| `python gecit.py --test site.com` | Belirli bir siteyi dener |
| `python gecit.py -v` | Her bağlantıyı yazar, sorun ararken işe yarıyor |
| `python gecit.py --uninstall` | Her şeyi geri alır |

`--test` çıktısı şuna benziyor:

```
discord.com
  sistem DNS: 195.175.254.2   DoH: 162.159.136.232
  none: X (ConnectionResetError) | tls: OK (117 ms) | tcp: X (ConnectionResetError) | tls+tcp: OK (170 ms)
  Geçit üzerinden: HTTP/1.1 200 OK
```

`none` hiçbir şey yapmadan bağlanmayı deniyor, `X` engelli demek. Başlarken çalışan yöntemi Geçit kendisi seçiyor

## Neyi yapamıyor

Sınırları var, saklamayayım:

- **Düz HTTP (`http://`) engellerini aşamıyor.** Türk Telekom 80. portta isteğin tamamını okuyor, bölmek işe yaramıyor. Tarayıcılar zaten çoğu siteyi kendiliğinden HTTPS'e çeviriyor, pratikte pek sorun olmuyor.
- **IP'si engellenmiş siteler açılmaz.** Onun için gerçekten bir sunucu lazım, yani VPN.
- **Proxy ayarını kullanmayan programlar** (bazı oyunlar, bazı uygulamalar) Geçit'ten geçmiyor.
- Engelli bir siteye **sadece TLS 1.2** ile bağlanan programlar takılır. Discord'un güncelleyicisi için özel çözüm var, başkaları için yok.

Discord'un ses sunucuları engelli değil zaten, sesli kanallara karışmıyor Geçit.

## Bilgisayarında neyi değiştiriyor

Hepsi bu kadar:

- Windows proxy ayarı (`AutoConfigURL`): Geçit açıkken ona yönleniyor, kapanınca siliniyor. Geçit çökse bile internetin kesilmiyor, Windows doğrudan bağlantıya dönüyor.
- `hosts` dosyasında tek satır: `127.0.0.1 updates.discord.com # gecit`
- Güvenilen sertifikalar arasında bir sertifika: `Gecit (yalnizca updates.discord.com)`
- Windows açılışında başlatma kaydı (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Gecit`)

`python gecit.py --uninstall` bunların hepsini geri alıyor. Dışarıyla Geçit'in kendi başına konuştuğu tek şey DNS sorguları; onlar da şifreli gidiyor Cloudflare'e (1.1.1.1), Google'a (8.8.8.8) ve Quad9'a (9.9.9.9).

Hafif bir şey bu arada. 35 MB civarı bellek kullanıyor, internet hızını düşürmüyor.

## Son olarak

Kendi derdim için yaptım, işine yararsa ne mutlu. Sorun yaşarsan `python gecit.py --test` çıktısıyla birlikte bir issue aç, bakarım.
