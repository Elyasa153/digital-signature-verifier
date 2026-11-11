package com.trustlayer.dsv.ra;

import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.trustlayer.dsv.ca.CertificateAuthority;
import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.institution.Institution;
import com.trustlayer.dsv.institution.InstitutionRegistry;
import com.trustlayer.dsv.ra.Application.Status;

/**
 * Kayıt otoritesi (K11): kurumun kimliğini doğrulayan ve başvuruyu onaylayan rol. Sertifikayı CA imzalar;
 * RA yalnız onaylanmış başvuru için {@link InstitutionRegistry#enroll} çağırır.
 * Akış: başvuru → e-posta kodu (bant dışı doğrulama) → CA yöneticisi onayı → kayıt. Her adım denetim kaydına yazılır.
 */
@Component
public class RegistrationAuthority {

    private static final Logger log = LoggerFactory.getLogger(RegistrationAuthority.class);

    private static final Pattern ID = Pattern.compile("[a-z0-9-]{3,40}");
    private static final Pattern EMAIL = Pattern.compile("[^@\\s]+@[^@\\s]+\\.[^@\\s]+");
    static final Duration CODE_VALIDITY = Duration.ofMinutes(15);
    static final int MAX_ATTEMPTS = 5;

    private final InstitutionRegistry registry;
    private final CertificateAuthority ca;
    private final AuditLog audit;
    private final Path dir;
    private final SecureRandom random = new SecureRandom();

    RegistrationAuthority(InstitutionRegistry registry, CertificateAuthority ca, AuditLog audit,
            @Value("${dsv.runtime-dir}") Path runtimeDir) {
        this.registry = registry;
        this.ca = ca;
        this.audit = audit;
        this.dir = runtimeDir.resolve("ra").resolve("basvurular");
    }

    /** Başvuruyu kaydeder ve kurumsal e-postaya tek kullanımlık kod gönderir. */
    public synchronized Application apply(String id, String displayName, Algorithm algorithm, String contactName,
            String email) {
        id = trim(id);
        displayName = trim(displayName);
        contactName = trim(contactName);
        email = trim(email);
        if (!ID.matcher(id).matches()) {
            throw new IllegalArgumentException("Kısa kod 3-40 karakter olmalı: küçük harf, rakam, tire.");
        }
        if (displayName.length() < 3 || displayName.length() > 100) {
            throw new IllegalArgumentException("Kurum adı 3-100 karakter olmalı.");
        }
        if (contactName.isEmpty() || contactName.length() > 100) {
            throw new IllegalArgumentException("Yetkili kişi adı gerekli.");
        }
        if (!EMAIL.matcher(email).matches() || email.length() > 200) {
            throw new IllegalArgumentException("Geçerli bir kurumsal e-posta adresi girin.");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("Algoritma seçin.");
        }
        final String newId = id;
        if (registry.all().stream().map(Institution::id).anyMatch(newId::equals)) {
            throw new IllegalArgumentException("Bu kısa kodla kayıtlı bir kurum zaten var: " + id);
        }
        Stored existing = load(id);
        if (existing != null && existing.app.status() != Status.REDDEDILDI) {
            throw new IllegalArgumentException("Bu kısa kodla açık bir başvuru zaten var: " + id);
        }

        Application app = new Application(id, displayName, algorithm, contactName, email, Status.KOD_BEKLIYOR,
                Instant.now(), "");
        String oneTimeCode = String.format("%06d", random.nextInt(1_000_000));
        save(new Stored(app, hash(oneTimeCode), Instant.now().plus(CODE_VALIDITY), 0));
        // Sınır: e-posta sunucusu yok, kod sunucu günlüğüne yazılır; gerçekte kurumsal adrese SMTP ile gider.
        log.info("[DEMO e-posta] {} adresine doğrulama kodu: {} (başvuru {})", email, oneTimeCode, id);
        audit.record("başvuran <" + email + ">", "BASVURU", id, displayName + ", " + algorithm);
        return app;
    }

    /** Kurum e-postadaki kodu girer: adresi kontrol ettiğini kanıtlar (ACME'deki challenge'ın kurum hâli). */
    public synchronized Application confirm(String id, String code) {
        Stored s = require(trim(id));
        if (s.app.status() != Status.KOD_BEKLIYOR) {
            throw new IllegalArgumentException("Bu başvuru kod beklemiyor.");
        }
        if (Instant.now().isAfter(s.codeExpires)) {
            throw new IllegalArgumentException("Kodun süresi doldu; yeniden başvurun.");
        }
        if (!MessageDigest.isEqual(s.codeHash.getBytes(StandardCharsets.US_ASCII),
                hash(trim(code)).getBytes(StandardCharsets.US_ASCII))) {
            int attempts = s.attempts + 1;
            if (attempts >= MAX_ATTEMPTS) {
                save(new Stored(s.app.with(Status.REDDEDILDI, "Çok fazla hatalı kod denemesi."), s.codeHash,
                        s.codeExpires, attempts));
                audit.record("başvuran <" + s.app.email() + ">", "KOD_KILITLENDI", s.app.id(), attempts + " hatalı deneme");
                throw new IllegalArgumentException("Çok fazla hatalı deneme; başvuru kapatıldı.");
            }
            save(new Stored(s.app, s.codeHash, s.codeExpires, attempts));
            throw new IllegalArgumentException("Kod hatalı. Kalan deneme: " + (MAX_ATTEMPTS - attempts));
        }
        Application confirmed = s.app.with(Status.ONAY_BEKLIYOR, "");
        save(new Stored(confirmed, "", s.codeExpires, s.attempts));
        audit.record("başvuran <" + s.app.email() + ">", "EPOSTA_DOGRULANDI", s.app.id(), "");
        return confirmed;
    }

    /** CA yöneticisi onaylar: anahtar kurum tarafında üretilir, CA CSR'ı imzalar (K4). */
    public synchronized Application approve(String id, String actor) {
        Stored s = require(id);
        if (s.app.status() != Status.ONAY_BEKLIYOR) {
            throw new IllegalArgumentException("Yalnız e-postası doğrulanmış başvuru onaylanabilir.");
        }
        registry.enroll(s.app.id(), s.app.displayName(), s.app.algorithm());
        Application approved = s.app.with(Status.ONAYLANDI, "");
        save(new Stored(approved, "", s.codeExpires, s.attempts));
        audit.record(actor, "ONAY", id, "sertifika verildi, " + s.app.algorithm());
        return approved;
    }

    public synchronized Application reject(String id, String actor, String reason) {
        Stored s = require(id);
        if (s.app.status() == Status.ONAYLANDI || s.app.status() == Status.REDDEDILDI) {
            throw new IllegalArgumentException("Başvuru zaten sonuçlanmış.");
        }
        Application rejected = s.app.with(Status.REDDEDILDI, trim(reason));
        save(new Stored(rejected, "", s.codeExpires, s.attempts));
        audit.record(actor, "RED", id, trim(reason));
        return rejected;
    }

    /** Kurum sertifikasını iptal eder; o kurumun bütün belgeleri doğrulamada REVOKED olur (UC-3). */
    public synchronized void revoke(String institutionId, String actor, String reason) {
        X509Certificate cert = registry.signingIdentity(institutionId).certificate();
        if (ca.currentCrl().isRevoked(cert)) {
            throw new IllegalArgumentException("Sertifika zaten iptal edilmiş: " + institutionId);
        }
        ca.revoke(cert.getSerialNumber());
        audit.record(actor, "IPTAL", institutionId, "seri " + cert.getSerialNumber().toString(16) + ", " + trim(reason));
    }

    public boolean isRevoked(String institutionId) {
        return ca.currentCrl().isRevoked(registry.signingIdentity(institutionId).certificate());
    }

    /** En yeni başta. */
    public synchronized List<Application> applications() {
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.toString().endsWith(".properties"))
                    .map(p -> load(p.getFileName().toString().replace(".properties", "")).app)
                    .sorted(Comparator.comparing(Application::createdAt).reversed())
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private record Stored(Application app, String codeHash, Instant codeExpires, int attempts) {
    }

    private Stored require(String id) {
        Stored s = ID.matcher(id).matches() ? load(id) : null;
        if (s == null) {
            throw new IllegalArgumentException("Başvuru bulunamadı: " + id);
        }
        return s;
    }

    private Stored load(String id) {
        Path file = dir.resolve(id + ".properties");
        if (!Files.exists(file)) {
            return null;
        }
        Properties p = new Properties();
        try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        Application app = new Application(id, p.getProperty("ad"), Algorithm.valueOf(p.getProperty("algoritma")),
                p.getProperty("yetkili"), p.getProperty("eposta"), Status.valueOf(p.getProperty("durum")),
                Instant.parse(p.getProperty("olusturma")), p.getProperty("not", ""));
        return new Stored(app, p.getProperty("kod-ozeti", ""), Instant.parse(p.getProperty("kod-son")),
                Integer.parseInt(p.getProperty("deneme", "0")));
    }

    private void save(Stored s) {
        Properties p = new Properties();
        p.setProperty("ad", s.app.displayName());
        p.setProperty("algoritma", s.app.algorithm().name());
        p.setProperty("yetkili", s.app.contactName());
        p.setProperty("eposta", s.app.email());
        p.setProperty("durum", s.app.status().name());
        p.setProperty("olusturma", s.app.createdAt().toString());
        p.setProperty("not", s.app.note());
        p.setProperty("kod-ozeti", s.codeHash);
        p.setProperty("kod-son", s.codeExpires.toString());
        p.setProperty("deneme", Integer.toString(s.attempts));
        try {
            Files.createDirectories(dir);
            try (Writer out = Files.newBufferedWriter(dir.resolve(s.app.id() + ".properties"), StandardCharsets.UTF_8)) {
                p.store(out, null);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String hash(String code) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(code.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }
}
