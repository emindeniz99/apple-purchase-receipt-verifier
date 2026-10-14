# Java BC legacy receipt — Temurin 17 review

14 Ekim 2026. İncelenen main: `4c7941894cbebe21fc1238aac6b4edc8f06880f1`.
İnceleme sonunda uzak main tekrar kontrol edildi; aynı commit'teydi.

Kapsam: `java/` içindeki legacy PKCS#7 receipt yolu, kullandığı ortak
trust/config/result kodu ve 13–14 Ekim eklemeleri. Rust davranışı ölçüt
olarak kullanılmadı. JWS bu raporun kapsamı dışında.

## Karar

**Temurin 17'de standart Apple legacy receipt doğrulaması için prod'a
çıkmayı engelleyen bir imza veya trust açığı bulmadım. Yeni güvenlik
korumalarını korurdum.** HTTP servisinde büyük girdilere karşı heap ve
eşzamanlılık sınırı gerekir: byte sınırı tek başına küçük bir JVM'i
korumuyor. Bu, mevcut README'de de belirtilen bir işletim koşulu.

Hedef “Apple'ın ürettiği geçerli receipt'leri kabul etmek” ise sonuç iyi:
gerçek Apple imzalı SHA-1/G1 ve SHA-256/G5 sandbox receipt'ler geçiyor,
imzası bozulmuş halleri reddediliyor ve signing date kullanıldığı için
sonradan sona eren sertifikalar eski receipt'i bozmuyor.

“Apple'ın kabul ettiği her olası ASN.1/CMS yeniden paketlemesini kabul
etmek” için daha geniş bir iddia kurulamıyor. Kütüphanenin kaynak sınırları
var. Bu incelemede Apple'ın canlı `verifyReceipt` endpoint'ine karşı
birebir kabul karşılaştırması yapılmadı. Production receipt sağlanmadı;
production'a özgü alan kombinasyonları özel bir canary ile kontrol
edilebilir. Gerçek Apple zincirleri sandbox verilerle test edildi.

## Doğrulama

- Eclipse Temurin **17.0.20.1+1**, HotSpot, Linux x86-64.
- BouncyCastle **bcprov/bcutil/bcpkix 1.86**; Jackson **2.22.3**.
- Maven **3.9.16**; kaynaklar Temurin 17 ile Java 8 hedefi için yeniden
  derlendi. `clean verify` başarılı; ana jar ve tests jar üretildi.
- **699 test, 0 failure, 0 error, 1 skip.** Skip, elle etkinleştirilen
  fixture üretim testi. 444 ortak case'in 224'ü `verifyReceipt`, 62'si
  `verifyReceiptEndpoint`; geri kalanı başka API ve base64 kontrolleri.
  Tam suite'in geçmiş olması bütün testlerin legacy testi olduğu anlamına
  gelmez.
- Ek probe: gerçek iki Apple sandbox receipt'i, ileri clock, bozuk imza,
  aynı imzaya eklenmiş 1.000/1.001 unsigned attribute.
- Haritasız creation-date denemesi: fixture ve deterministik mutasyon
  corpus'undan **3.344 payload, 2.210 okunabilen tarih, 0 fark**.
- İlk Temurin 21 çalışması da geçti; prod kararı Temurin 17 sonucuna dayanıyor.

## Bulgular ve sadeleştirme adayları

### 1. Önemli işletim riski: imza öncesi payload ayrıştırma pahalı

[`ReceiptCore.java`](../../java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptCore.java)
satır 143 ve
[`ReceiptDecoder.java`](../../java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoder.java)
satır 109–116.

`readCreationDate` yalnızca attribute 12'yi kullanıyor, fakat
`readAttributes` tüm top-level attribute'ları parse ediyor ve `firsts` /
`unknown` haritalarını dolduruyor. Bunlar bu aşamada atılıyor. Zincir ve
imza geçerse aynı payload yeniden okunuyor.

Bu işi bir saldırgan da tetikleyebilir: kendi zincirini taşıyan, byte
sınırını aşmayan bir receipt için önce payload okunuyor, sonra yabancı
root yüzünden `UNTRUSTED_CHAIN` dönüyor. Deneme girdisi yaklaşık 3 MiB
base64 ve 195.562 ek küçük attribute içeriyor.

| Temurin 17 ölçümü | Ortalama süre | Çağrı başına toplam tahsis |
|---|---:|---:|
| Gerçek legacy sandbox, 187 purchase | 7,1 ms | 4,6 MiB |
| Gerçek G5 sandbox | 2,9 ms | 0,4 MiB |
| Küçük attribute'larla cap'e yakın sahte receipt, Apple root'ları altında ret | 128,3 ms | 135,2 MiB |
| Aynı sentetik receipt, kendi test root'u altında kabul | 297,4 ms | 279,5 MiB |
| Cap'e yakın tek unsigned attribute, sahte zincir | 94,4 ms | 75,8 MiB |

Bunlar 30 warm-up sonrası 20 çağrılık düz döngü ölçümleri; JMH veya
throughput kapasite ölçümü değildir. Zamanlar makineye göre değişir.
**Tahsis toplamı, aynı anda canlı heap değildir.**

Aynı sahte receipt, tek bir çağrıda `-Xmx64m` ile `OutOfMemoryError`
verdi, `-Xmx128m` ile düzgün reddedildi. Tek cold-process bisection'ında
78 MiB başarısız, 79 MiB başarılıydı. Bu değer bütün girdiler için heap
garantisi değildir. OOM bir `Error` olduğu için public API'den çıkar;
normal `Failure` olmaz.

Öneri: HTTP tarafında byte sınırının yanında bounded executor / semaphore
kullanmak ve heap'i aynı anda doğrulanan büyük girdilere göre ayırmak.
Kütüphane içindeki en anlamlı performans adayı, creation date için
gereksiz haritaları oluşturmamak. Deneme:

| Yalnızca creation-date adımı | Süre | Toplam tahsis |
|---|---:|---:|
| Mevcut okuyucu | 119,08 ms | 114,28 MiB |
| Tüm top-level yapıyı kontrol eden, harita oluşturmayan deneme | 62,57 ms | 85,93 MiB |

Deneme ilk attribute 12'nin kazanmasını ve sonraki bozuk bir attribute'ın
tarihi geçersiz kılmasını koruyor. Corpus eşitliği iyi kanıt, bütün
olası girdiler için ispat değil. Bu değişiklik daha fazla okuyucu kodu
gerektirir; normal receipt'ler için zorunlu bir prod düzeltmesi saymıyorum.
Önceki “payload'ı bir kez parse edip sonucu saklama” denemesi farklıdır:
o yaklaşım imza öncesi maliyeti azaltmadığı için geri alınmıştı.

### 2. Kabul sınırları bilinçli; “bütün geçerli imzalı paketler” iddiası fazla geniş

[`ReceiptCore.java`](../../java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptCore.java)
satır 200–253 ve
[`ReceiptCertificates.java`](../../java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptCertificates.java)
satır 25–42.

Gerçek G1 ve G5 receipt'lerin payload ve imzasını koruyup yalnızca unsigned
attribute ekledim. 1.000 attribute ile ikisi de `VERIFIED`, 1.001 ile
ikisi de `MALFORMED`. İmza geçerliliği korunurken kütüphane kaynak
politikası yüzünden paketi reddedebiliyor. Bu yeni bir gizli açık değil;
mevcut sınırın somut sonucu.

10 embedded certificate, 4 SignerInfo, 1.000 certificate extension ve
1.000 toplam SignerInfo attribute sınırları da aynı türden. Apple'ın
mevcut receipt şekilleri bunların oldukça altında. Bunları kaldırmak
önerim değil. Kabul hedefini “desteklenen kaynak sınırları içinde
Apple-imzalı receipt” olarak ifade etmek daha doğru.

`SignedAsSent` ayrıca non-DER signed attribute'ların kabul davranışını
değiştiriyor: BC'nin DER'e sıralama maliyetini önlüyor. DER biçimindeki
signed attribute aynı bytes'a dönüşüyor. Non-DER input için önceki
BC kanonikleştirmesiyle birebir aynı davranış yok; bu mevcut evidence'da
da kayıtlı. İki gerçek Apple fixture'ında signed attribute bulunmuyor.
Bu nedenle mevcut Apple receipt'leri için kırılma kanıtı bulmadım;
genel CMS doğrulayıcısı için “tam RFC/BC davranışı” iddiası kurmam.

### 3. Kaynakta tekrar eden uzun açıklamalar sadeleştirilebilir

13 Ekim başındaki `1cb08f0e` ile incelenen main arasında, bütün Java
değişikliklerinde 2.217 satır eklenmiş ve 67 silinmiş. Net büyümenin
1.686 satırı testlerde, 464 satırı main/shared kaynaklarda.

JWS'yi çıkartıp legacy yoluyla ilgili yedi değişen üretim dosyasına
bakınca net büyüme **440 fiziksel satır**. Yorum ve boş satırlar
ayıklanarak sayılan net kod büyümesi **236 satır**. Sayım yaklaşık bir
Java comment tokenizer'ıyla yapıldı; AST tabanlı complexity metriği değil.

Özellikle `AppleTrust` ve `ReceiptCore` içindeki uzun benchmark rakamları,
draft tarihçesi ve aynı saldırının ayrıntılı açıklaması mevcut evidence
belgelerinde tekrar bulunuyor. Kaynakta kısa “neden” açıklaması, RFC
referansı ve ilgili evidence linki bırakmak okunabilirliği artırır.
PSS formülü, güvenilmeyen key'in neden okunmadığı ve DER/DL farkı gibi
kararı anlamak için gerekli notlar kalmalı.

Üretim yolunda açıkça kullanılmayan bir sınıf veya silinmesi güvenli bir
güvenlik dalı tespit etmedim. Gözlenen büyümenin önemli kısmı çalışırken
yüklenmeyen testler ve açıklamalar.

### 4. Benchmark testlerinin bakım maliyeti var

[`DigestDenylistCostTest.java`](../../java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/DigestDenylistCostTest.java)
satır 32–87, provider'ın OID'lerini ve BC'nin private digest tablolarını
tarayıp çalışma zamanı oranlarına göre karar veriyor. Test yararlı:
dependency upgrade yeni pahalı bir yol eklerse haber veriyor. Ancak
normal fonksiyon testine göre JIT, runner yükü ve BC internal API'sine
daha bağlı. Kaynakta daha önce Temurin 17'de bir oran yüzünden fail
olduğu ve toleransın değiştirildiği de yazıyor.

Bu incelemede güncel test geçti; mevcut bir fail raporlamıyorum. Bakım
önerim, bu geniş taramayı dependency upgrade / periyodik benchmark
kontrolünde çalıştırmayı değerlendirmek. Deterministik negatif testler
ve gerekli DoS regresyon testleri normal CI'da kalmalı. Bu kod shipped
jar'a girmiyor; silmek prod kodunu küçültmez.

## Son eklemelerin hangileri gerekli?

| Kod | Neden gerekli / karar |
|---|---|
| `saltFits` ve content-verifier wrapper | Unsigned PSS salt uzunluğuyla devasa array tahsisini engelliyor. Wrapper BC'nin gerçekte çözdüğü algoritmayı kontrol ettiği için alias OID'lerini de kapsıyor. Kalsın. |
| Generic composite label reddi | Sender'ın istediği sayıda signature verifier üretmesini ve tekrar tekrar content hash'lemesini engelliyor. Kalsın. |
| Sekiz pahalı digest ve MD2 signature label reddi | Geçersiz signature karşılaştırılmadan önce yapılacak pahalı hash'i kesiyor. Signature label için ayrı kontrol tekrar değil. Kalsın. |
| `stringsOnly`, `holdsSet`, `convertible` | Unsigned isim / parametre içindeki nested SET'lerin pahalı DER encoding'ini önlüyor. BC object conversion da encode yaptığı için sadece ilk encode'u kaldırmak yetmiyor. Kalsın. |
| Extension ve attribute count sınırları | BC'nin OID keyed `Hashtable` yapısında collision maliyetini sınırlıyor. Varsayılan receipt byte sınırı bunun yerine geçmiyor. Kalsın. |
| Signer ve issuer kopyalarını tekrar denememek | Unsigned bag'e eklenebilen aynı sertifikanın gereksiz chain / signature kontrollerini azaltıyor. Kalsın. |
| Her signer için tek üyeli CMS oluşturmak | BC'nin çok signer'lı store'unda issuer karşılaştırmasının pahalı yolundan kaçıyor. Alışılmadık görünüyor ama gerekçesi var. Kalsın. |
| `SignedAsSent` | Signed attribute'ların nested SET sıralamasını imza öncesinde çalıştırmayı önlüyor. DER/DL farkı ve non-DER kabul kapsamı açık tutulmalı. |

PSS'yi tamamen reddetmek veya yalnızca bugün gözlenen SHA-1/SHA-256
algoritmalarını allowlist'e almak kodu daraltabilir, ama yeni bir Apple
signing algoritmasını gereksiz reddetme riskini artırır. Mevcut küçük
resource guard'lar belirtilen kabul hedefiyle daha uyumlu.

## Akışın doğruluğu

- UTF-8 byte sınırı base64 decode'dan önce. Standard base64 padding
  kontrolü mevcut; unused-bit kabulü repo'nun Apple ölçümünü izliyor.
- CMS envelope bir kez parse ediliyor; trailing bytes ve detached
  content reddediliyor. BER encapsulated content destekleniyor.
- Creation date ilk attribute 12'den alınıyor. Eksik / okunamayan date
  clock'a düşüyor. Şimdiki clock geçerli historical date'i override etmiyor.
- Embedded certificate'lerin public key'leri, pinned root veya onun
  imzasını doğruladığı CA tarafından vouch edilmeden kullanılmıyor.
  End entity bir sonraki sertifikayı vouch edemiyor.
- Top-down signature proof sonrası ayrıca PKIX validation yapılması
  gerekli. İlk geçiş güvenilmeyen key decode maliyetini engelliyor;
  PKIX ise date, CA, key usage, constraints ve critical extension'ları
  değerlendiriyor. İlk geçişi PKIX yerine kullanmak güvenli sadeleştirme olmaz.
- PKIX target tam signer certificate. Aynı issuer/serial/subject taşıyan
  başka key'li twin ile trust kontrolünü başka key'e uygulama açığı yok.
- Leaf ve signer'ı doğrudan izleyen intermediate Apple marker kontrolü
  var. Sıradan developer certificate aynı root'a zincirlense bile receipt
  signer olarak kabul edilmiyor.
- Bir passing SignerInfo yeterli; sertifika eşleşmelerinin tamamı
  deneniyor. Bozuk / desteklenmeyen signature'ın yanındaki geçerli signer
  deterministic testlerle korunuyor.
- Payload modeli yalnızca CMS signature geçtikten sonra üretiliyor.
  Bundle, environment, product ve device hash verifier'ın iş politikası
  değil; caller'a bırakılan alanlar. Bilinmeyen veya okunamayan alanların
  raw değerleri korunuyor. Mutable byte array'lerin defensive copy'leri
  gereksiz değil.

Apple'ın [receipt validation dokümanı](https://developer.apple.com/documentation/appstorereceipts/validating-receipts-on-the-device)
özellikle SHA-1 ve SHA-256 zincir desteği, intermediate'ları hardcode
etmeme ve signature doğrulamasında attribute 12 kullanma kurallarını
belirtiyor. Bu üç noktayı mevcut Java yolunda doğru buldum. Dokümandaki
bundle/version/device kontrolleri ise on-device app entitlement
validation'ın parçaları; bu kütüphanenin “Apple imzası + payload”
sözleşmesinde caller'ın sorumluluğu olarak açıkça belirtilmiş.

## Önerilen sıra

1. Prod servisinde büyük girdiler için eşzamanlılık ve heap bütçesini
   doğrula; örnekler gerçek receipt büyüklüklerinin garantisi değil.
2. Mevcut crypto ve pre-trust guard'ları koru.
3. Uzun açıklama tekrarlarını mevcut dokümantasyona taşı.
4. Gerekirse creation-date harita tahsisini azalt; corpus eşitliği ve
   imza öncesi / sonrası hata sırasını koruyan testlerle ayrı değerlendir.
5. Algoritma tarama benchmark'ının CI konumunu değerlendir.

Üretim Java kaynakları değiştirilmedi. İnceleme kodu ve tekrar çalıştırma
talimatları [bu klasörde](2026-10-14-java-legacy-temurin17-review/README.md).
Deneme receipt'leri, JDK/BC indirmeleri, class dosyaları ve raw ölçüm
logları repository dışında tutuldu.

## İkinci tur: legacy receipt güvenlik incelemesi

Bu bölüm aynı `4c7941894cbebe21fc1238aac6b4edc8f06880f1` main üzerinde,
Temurin 17.0.20.1+1 ve BC 1.86 ile yapılan ek incelemedir. Rust ve JWS
bu turun kapsamı değildir. Tehdit modeli: saldırgan base64 girdisini,
CMS envelope, certificate bag ve SignerInfo'ları değiştirebilir; Apple
private key'ine, uygulamanın root config'ine veya JVM ayarlarına erişemez.
Public sandbox receipt'leri ve sentetik test PKI kullanıldı.

### Bulgular ve karar

**Yeni bir imza veya güven zinciri atlatması gösterilemedi.** İncelenen
akışta `VERIFIED` döndürebilmek için aynı signer sertifikasının root'a
zincirlenmesi, marker kontrollerinden geçmesi ve payload'ın CMS imzasını
doğrulaması gerekiyor. Bu sonuç bütün olası girdilerin güvenli olduğuna
dair bir ispat değildir; aşağıdaki testler ve kaynak incelemesiyle sınırlı.

**Prod için açık kalan konu: doğrulama öncesi bellek tüketimi.**
[ReceiptCore](../../java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptCore.java)
envelope'u, ardından `ReceiptDecoder.readCreationDate` bütün attribute
SET'ini trust kurulmadan parse ediyor. Önceki turda cap altındaki sentetik
bir forgery için 135.2 MiB toplam allocation ve 64 MiB heap'te OOM
gösterildi. Bu bir entitlement veya signature bypass değil; saldırgan
girdisi kabul eden servis için availability riski. `RuntimeException`
yakalamak `OutOfMemoryError`'ı önlemez. Heap ve eşzamanlılık bütçesi
doğrulanmadan koşulsuz "prod ready" kararı verilmemeli. README bu riski
zaten belgeliyor; yeni keşfedilmiş bir tasarım kusuru olarak sunulmuyor.
Concurrency'yi sadece CPU sayısından seçmek yerine uygulamanın boş heap
bütçesine göre de sınırlandırmak gerekir. Allocation toplamı eşzamanlı
istek sayısıyla çarpılıp peak heap tahmini olarak kullanılamaz.

**Sadeleştirme adayı: creation-date için geçici map'ler.**
[ReceiptDecoder.readCreationDate](../../java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoder.java)
tek tarih için diğer bütün attribute değerlerini map/list'lere topluyor.
Önceki tarayıcı deneyi aynı corpus'ta aynı sonucu daha az allocation ile
verdi. Bu değişiklik ASN.1 ağacının ilk parse maliyetini kaldırmaz ve
tek başına DoS çözümü değildir. İlk attribute'un kazanması, hatalı sonraki
attribute'un tarihi fallback'e götürmesi ve hata sırası korunmalı.

**Apple kabulüyle bire bir eşitlik bugün yok.** Somut örnek:
`ASN1Primitive.fromByteArray` CMS sonundaki ek baytları reddediyor.
Repo'nun [2026-09-23 Apple endpoint ölçümü](2026-09-23-verifyreceipt-base64.md)
aynı receipt'e eklenen baytların Apple tarafından yok sayıldığını
belgeliyor; `receipt/reject-one-trailing-byte-after-the-der` bunu bilinçli
fark olarak pinliyor. Bu tur Apple endpoint'ine tekrar istek yapılmadı.
Bu, yalnızca olası bir gelecek uyumsuzluğu değil, kayda geçmiş kabul
farkıdır. Kullanıcının hedefi tam Apple kabul eşitliğiyse bu davranış
ayrıca karara bağlanmalı. Kaynak sınırlarını kaldırmak bu sorunu çözmez.

### Yeni deneyler

Kaynak:
[SecurityReviewProbe.java](2026-10-14-java-legacy-temurin17-review/SecurityReviewProbe.java).
`run.py --security-only` ile tekrar çalışır. Derlenen üretim sınıfları
değiştirilmedi. İlk sonuçlar `binding.log` ve `oid-costs.log`; tekrar
çalıştırma `results.txt` olarak repository dışındaki scratch dizinine
yazıldı. Loglar receipt alanlarını veya kullanıcı kimliklerini yazmaz.

| Deney | Sonuç |
|---|---|
| Gerçek legacy ve G5 receipt'lerinde payload boyunca 128 konumda bir bit değiştirme | Hiçbiri `VERIFIED` olmadı |
| Aynı receipt'lerin RSA signature'ında her byte konumunda bir bit değiştirme | Hiçbiri `VERIFIED` olmadı |
| Detached content veya boş certificate bag | Kabul edilmedi |
| Aynı signed content'i parçalara ayrılmış BER OCTET STRING olarak taşıma | İki gerçek receipt ve sentetik kontrol kabul edildi |
| Signed-attribute'lu sentetik receipt'te payload ve messageDigest'i birlikte değiştirme, signature'ı koruma | Kabul edilmedi |
| Signed messageDigest, contentType veya cmsAlgorithmProtect attribute'unu çoğaltma | Kabul edilmedi; bu deney signature'ı da değiştirdiği için tek başına duplicate kontrolünün çalıştığını ispatlamaz |
| Sentetik PKI ile imzalanmış receipt'i default Apple root'larına sunma | Kabul edilmedi |
| Test anahtarıyla üretilen RSA blokları: SHA-1 digest'inin her 20 byte'ını ayrı değiştirme ve dört bozuk padding/DigestInfo biçimi | 24 bozuk blok reddedildi; geçerli kontrol kabul edildi |
| Aynı RSA deneyi SHA-256 için | 36 bozuk blok reddedildi; geçerli kontrol kabul edildi |

Toplam **1,119 assertion** geçti. Başarısız doğrulamalarda payload
dönmedi, `INTERNAL_ERROR` oluşmadı, unchecked exception kaçmadı. RSA
deneyi yalnızca signature byte'ını bozmaz: test private key'iyle istenen
EMSA-PKCS1-v1_5 bloğunu üreten signature hazırlanır. Böylece RSA işlemi
sonrasındaki digest byte ve padding kontrolleri özellikle sınanır.

OID tablosu için önceki kaynak tahminini gerçek collision girdisiyle
sınadım: BC `hashCode()` değeri aynı olan **1,000 farklı OID**, her biri
**2,300 content octet**. OID'lerin uzun ortak prefix'i equality kontrolünü
pahalı yapar. OID'ler gerçek G5 receipt'in imzasız attribute alanına
eklendi; Apple'ın signed content'i ve signature'ı değişmedi. Kontrol
grubu aynı sayıda ve uzunlukta farklı hash'li OID taşır.

| İmzasız attribute sayısı | Base64 byte | Kontrol, ms/çağrı | Hash collision, ms/çağrı |
|---|---:|---:|---:|
| 250 | 778,236 | 11.3 | 10.8 |
| 500 | 1,548,900 | 12.6 | 29.2 |
| 1,000 | 3,090,236 | 20.5 | 82.4 |

Her girdide sonuç `VERIFIED`; hepsi 3,145,728 byte cap altında. Beş
warmup sonrası on çağrının ortalaması, 512 MiB heap. Bunlar JMH veya
worst-case latency garantisi değil. Bu deney quadratic tablonun yalnızca
teorik olmadığını ve mevcut cap'in bu saldırıda işi sınırladığını
gösteriyor. 1,000 sınırını gereksiz kod diye kaldırmak için gerekçe yok.

### Güven sınırları: kaynak incelemesinin sonucu

| Sınır | Kontrol ve değerlendirme |
|---|---|
| Payload ↔ CMS signature | Dönen payload, `CMSSignedData` içindeki aynı byte dizisidir. Signed attribute varsa BC messageDigest'i hesaplanan digest ile karşılaştırır; yoksa payload'ın doğrudan imzasını doğrular. |
| Signer identity ↔ key | Issuer/serial veya SKI eşleşmesi yalnızca aday seçer. PKIX target tam certificate'tir; adayın kendi public key'i CMS için kullanılır. Aynı isim/serial taşıyan başka key trust yerine geçemez. |
| Apple developer key ↔ receipt signing key | Top-down yürüyüşte end entity bir sonraki certificate'i onaylayamaz. Receipt leaf ve doğrudan issuer WWDR marker'ları ayrıca gerekir. |
| Top-down ↔ tam PKIX | İlk aşama yalnızca issuer signature proof sağlar. İkinci aşama validity, CA/key usage/constraints/critical extensions içindir. Birini kaldırmak güvenli sadeleştirme değildir. |
| Unsigned algorithm labels ↔ BC provider | PSS salt bound BC'nin çözdüğü gerçek algorithm üstünde, verifier kurulmadan uygulanır. Generic composite ayrıca reddedilir; raw OID kontrolü tek başına yeterli değildir. |
| CMS attribute processing | `SignedAsSent` DER sorting maliyetinden kaçınır; BC'nin contentType, messageDigest, algorithm protection ve countersignature kontrolleri yine çalışır. DL kullanımı genel non-DER CMS kabulünde standart BC ile eşitlik garantisi vermez. |
| Certificate URL ↔ network | İncelenen builder'a yalnızca Collection CertStore veriliyor, named store yok, revocation kapalı. BC issuer araması bu store'ları kullanıyor; bu yolda saldırgan certificate URL'sine HTTP fetch ekleyen bir çağrı bulmadım. Bu madde kaynak incelemesidir, network instrumentation sonucu değildir. |
| Paylaşılan verifier ↔ çağrı state'i | Trust config sabit; CMS, signer verifier ve PKIX builder çağrıya özel. Critical-extension checker state tutmuyor. Mevcut concurrency/isolation testleri önceki Temurin 17 suite'inde geçti. |

### Prod kararı ve gereksiz kod

İmza/güven zinciri için bu incelemede yeni bir release blocker bulunmadı.
Temurin 17 üzerindeki önceki **699 test / sıfır failure / bir skip**
sonucuna bu turun 1,119 security assertion'ı ekleniyor; bunlar yeni JUnit
test sayısı değildir. Public fixture'lerin gerçek Apple zincirlerini
geçirmesi SHA-1 legacy ve G5 için önemli bir kontrol; bütün Apple receipt
çeşitlerini kapsadığı anlamına gelmez.

PSS, generic composite, unauthenticated key decode, strict signer lookup,
tam certificate target, certificate/SignerInfo/attribute cap'leri ve
top-down + PKIX korunmalı. Bu turda güvenle silinebilecek, açıkça ölü bir
production security branch bulunmadı. Önceki sadeleştirme önerileri
geçerli: creation-date map allocation'ı ve kanıt dokümanlarıyla tekrarlanan
uzun yorumlar. BC signed-attribute verification'ını el yazımı bir CMS
doğrulayıcıyla değiştirmek daha küçük bir güvenlik yüzeyi sağlamaz.

`VERIFIED` yalnızca kütüphanenin belgelenmiş imza/trust sözleşmesidir.
Bundle, sandbox/production, product, transaction'ın hangi kullanıcıya
verildiği ve idempotency uygulamada kontrol edilmelidir. Offline doğrulama
sonradan gerçekleşen refund/revocation veya en güncel abonelik durumunu
öğrenmez. Bunlar yeni bulgu değil, güvenlik değerlendirmesinin sınırıdır.

## Hangi kod gerçekten fazla?

Apple'ın normal receipt'inde kullanılmayan bir dal, saldırganın doğrulama
öncesinde çalıştırabileceği bir BC yolunu sınırlıyorsa gereksiz değildir.
Öte yandan her ek satır kriptografik zorunluluk da değildir. Bu ayrım
üzerinden somut sadeleştirme kararı:

| Kod | Apple imzasını doğrulamak için rolü | Öneri |
|---|---|---|
| `readCreationDate` içindeki tüm attribute map/list'leri | Yalnızca ilk attribute 12 gerekli; diğer değerlerin bu aşamada biriktirilmesi gerekli değil | Tam structural kontrolü koruyan, map tutmayan taramayla sadeleştirme adayı. Deneyde allocation azaldı; production değişikliği bu branch'te yapılmadı. |
| `DigestDenylistCostTest` (315 satır) | Runtime doğrulamaya katılmaz. Algoritma maliyetlerini tarayan bakım benchmark'ı | Normal test suite'inden ayrı, BC upgrade'inde veya planlı çalışan benchmark'a taşıma adayı. Deterministik kötü-input ret testlerini normal suite'te tut. Mevcut suite bu ortamda geçti; öneri gözlenmiş bakım karmaşıklığına dayanıyor. |
| Production yorumlarındaki uzun benchmark/geçmiş anlatımı | Runtime davranışını değiştirmez; evidence dokümanlarında aynı gerekçeler zaten var | Kısa invariant + kanıt bağlantısı bırakılabilir. Güvenlik gerekçesini tamamen silme. |
| `REFUSED_DIGESTS` ve MD2 signature label reddi | Apple'ın imza geçerliliği şartı değil; doğrulama öncesi CPU maliyetini sınırlayan yerel politika | Küçük tabloyu koru. Silmek imza güvenliğini doğrudan kaldırmaz ama ölçülmüş pahalı digest yollarını yeniden açar. Tabloyu genişletmek için ölçüm iste. |
| `SignedAsSent`, tek SignerInfo'lu CMS wrapper, `stringsOnly` / `holdsSet` | BC'nin doğrulama öncesindeki sorting, hashing ve name comparison maliyetlerini sınırlar | Mevcut BC 1.86'da gerekçeleri var; sırf Apple normalde bu biçimleri üretmiyor diye kaldırma. Özellikle `SignedAsSent` genel CMS davranışına müdahale ettiği için BC upgrade'lerinde yeniden değerlendir. |
| PSS salt kontrolü, generic composite reddi, top-down + PKIX, exact certificate target ve kaynak cap'leri | Bazıları trust bağını kurar, bazıları imza kontrolüne ulaşmadan OOM/aşırı CPU'yu engeller | Koru. İncelemede güvenle silinebilecek ölü bir branch bulunmadı. |

13–14 Ekim karşılaştırmasında legacy ile ilgili production büyümesi
yaklaşık **440 fiziksel satır**, yorum ve boşluklar çıkarılınca yaklaşık
**236 kod satırı**. Java testlerindeki net büyüme **1,686 satır**.
Dolayısıyla görünen büyümenin büyük kısmı runtime'a eklenen yeni doğrulama
mantığı değil. Bu sayılar önceki bölümdeki aynı commit aralığına aittir;
yorum ayrımı yaklaşık lexical ölçümdür.

Bu review branch'indeki probe'lar da yalnızca `docs/evidence/` altında
kalır; Maven production kaynaklarına veya yayımlanan ana JAR'a girmez.
Branch rapor ve tekrar üretilebilir kanıt taşır, production refactor taşımaz.
