# digital-signature-verifier

BMÜ-401 Proje 29: Dijital İmza ile Elektronik Belgelerin Doğrulanması.

Kurumlar belgeyi şablon ve veri kaynağından otomatik üretip PAdES ile imzalar; belgeyi alan kişi hesap açmadan
doğrulama sayfasında belgenin değişmediğini ve kimin imzaladığını görür.

- Java 17+, Spring Boot, Bouncy Castle, Apache PDFBox, ZXing

```
./mvnw test              # Windows: mvnw.cmd test
./mvnw spring-boot:run   # http://localhost:8080
```

Gizli anahtarlar ve `runtime/` klasörü repoya girmez.
