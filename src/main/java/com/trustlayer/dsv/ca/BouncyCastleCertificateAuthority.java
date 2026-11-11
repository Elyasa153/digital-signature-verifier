package com.trustlayer.dsv.ca;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Kök CA (İP-5, FR-1, FR-2). Kök anahtar {@code <runtime>/ca/root.p12} içinde, ilk kullanımda üretilir.
 * İptal edilen seriler {@code <runtime>/ca/revoked.txt} dosyasında, her satırda bir onaltılık seri.
 */
@Component
class BouncyCastleCertificateAuthority implements CertificateAuthority {

    /** DER sırası genelden özele: C, O, CN. */
    private static final X500Name ROOT_DN = new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.C, "TR").addRDN(BCStyle.O, "TrustLayer").addRDN(BCStyle.CN, "TrustLayer Root CA").build();
    private static final String ALIAS = "root";
    private static final Duration ROOT_VALIDITY = Duration.ofDays(3650);
    private static final Duration INSTITUTION_VALIDITY = Duration.ofDays(730);
    /** Saat kayması: doğrulayanın saati biraz geride olsa da sertifika "henüz geçerli değil" olmasın. */
    private static final Duration CLOCK_SKEW = Duration.ofDays(1);
    private static final Duration CRL_REFRESH = Duration.ofDays(1);

    private final Path dir;
    private final char[] password;
    private final String crlUrl;
    private final SecureRandom random = new SecureRandom();

    private PrivateKey rootKey;
    private X509Certificate rootCert;
    /** Son yayımlanan CRL; iptalde ya da süresi yaklaşınca yenilenir. */
    private X509CRL crl;

    BouncyCastleCertificateAuthority(@Value("${dsv.runtime-dir}") Path runtimeDir,
            @Value("${dsv.keystore-password}") String password, @Value("${dsv.crl-url}") String crlUrl) {
        this.dir = runtimeDir.resolve("ca");
        this.password = password.toCharArray();
        this.crlUrl = crlUrl;
    }

    @Override
    public synchronized X509Certificate rootCertificate() {
        loadOrCreateRoot();
        return rootCert;
    }

    @Override
    public synchronized X509Certificate issue(PKCS10CertificationRequest csr, String institutionId) {
        loadOrCreateRoot();
        try {
            // CSR'ı imzalayan, içindeki açık anahtarın sahibi olmalı (K4).
            JcaPKCS10CertificationRequest request = new JcaPKCS10CertificationRequest(csr);
            PublicKey publicKey = request.getPublicKey();
            if (!request.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey))) {
                throw new IllegalArgumentException("CSR imzası geçersiz: " + institutionId);
            }

            Instant now = Instant.now();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(rootCert, serial(),
                    Date.from(now.minus(CLOCK_SKEW)), Date.from(now.plus(INSTITUTION_VALIDITY)),
                    request.getSubject(), publicKey);
            JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            // Kurum sertifikası başka sertifika imzalayamaz.
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
            builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(publicKey));
            builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(rootCert));
            GeneralName crl = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {
                    new DistributionPoint(new DistributionPointName(new GeneralNames(crl)), null, null) }));
            return toCertificate(builder.build(rootSigner()));
        } catch (GeneralSecurityException | OperatorCreationException | PKCSException | IOException e) {
            throw new IllegalArgumentException("Sertifika verilemedi: " + institutionId, e);
        }
    }

    @Override
    public synchronized void revoke(BigInteger serialNumber) {
        try {
            Files.createDirectories(dir);
            // Satır: "<seri, onaltılık> <iptal anı, epoch ms>". Tarih CRL'de iptal tarihi olarak kalıcıdır.
            String line = serialNumber.toString(16) + " " + System.currentTimeMillis() + "\n";
            Files.writeString(dir.resolve("revoked.txt"), line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            crl = null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // İptal önbelleği siler, bir sonraki doğrulama yeni CRL'yi hemen görür (UC-3). İptal yoksa CRL bir gün geçerli
    // kalır: her doğrulamada RSA-4096 ile yeniden imzalamak doğrulama süresinin ~%75'iydi (ölçüldü, 11-11).
    @Override
    public synchronized X509CRL currentCrl() {
        loadOrCreateRoot();
        if (crl != null && crl.getThisUpdate().toInstant().plus(CRL_REFRESH).isAfter(Instant.now())) {
            return crl;
        }
        crl = issueCrl();
        return crl;
    }

    private X509CRL issueCrl() {
        try {
            Instant now = Instant.now();
            JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(rootCert, Date.from(now));
            builder.setNextUpdate(Date.from(now.plus(Duration.ofDays(7))));
            for (Map.Entry<BigInteger, Date> revoked : revocations().entrySet()) {
                builder.addCRLEntry(revoked.getKey(), revoked.getValue(), CRLReason.privilegeWithdrawn);
            }
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(rootCert));
            // CRL numarası her yayında artmalı (RFC 5280 §5.2.3); milisaniye zamanı bunu sağlar.
            builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(now.toEpochMilli())));
            return new JcaX509CRLConverter().getCRL(builder.build(rootSigner()));
        } catch (GeneralSecurityException | OperatorCreationException | IOException e) {
            throw new IllegalStateException("CRL üretilemedi", e);
        }
    }

    /** Seri → iptal anı. Tarihsiz eski satırlarda dosyanın son değişme anı kullanılır (gerçek iptalden önce olamaz). */
    private Map<BigInteger, Date> revocations() throws IOException {
        Path file = dir.resolve("revoked.txt");
        Map<BigInteger, Date> result = new LinkedHashMap<>();
        if (!Files.exists(file)) {
            return result;
        }
        Date legacy = new Date(Files.getLastModifiedTime(file).toMillis());
        for (String line : Files.readAllLines(file)) {
            String[] parts = line.trim().split("\\s+");
            if (!parts[0].isEmpty()) {
                result.putIfAbsent(new BigInteger(parts[0], 16),
                        parts.length > 1 ? new Date(Long.parseLong(parts[1])) : legacy);
            }
        }
        return result;
    }

    private void loadOrCreateRoot() {
        if (rootCert != null) {
            return;
        }
        if (password.length == 0) {
            throw new IllegalStateException("DSV_KEYSTORE_PASSWORD ortam değişkeni ayarlanmamış");
        }
        Path file = dir.resolve("root.p12");
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            if (Files.exists(file)) {
                try (InputStream in = Files.newInputStream(file)) {
                    ks.load(in, password);
                }
                rootKey = (PrivateKey) ks.getKey(ALIAS, password);
                rootCert = (X509Certificate) ks.getCertificate(ALIAS);
                return;
            }
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(4096, random);
            KeyPair pair = gen.generateKeyPair();
            rootKey = pair.getPrivate();

            Instant now = Instant.now();
            X500Name name = ROOT_DN;
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial(),
                    Date.from(now.minus(CLOCK_SKEW)), Date.from(now.plus(ROOT_VALIDITY)), name, pair.getPublic());
            JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(pair.getPublic()));
            rootCert = toCertificate(builder.build(rootSigner()));

            ks.load(null, null);
            ks.setKeyEntry(ALIAS, rootKey, password, new Certificate[] { rootCert });
            Files.createDirectories(dir);
            try (OutputStream out = Files.newOutputStream(file)) {
                ks.store(out, password);
            }
        } catch (GeneralSecurityException | OperatorCreationException | IOException e) {
            rootKey = null;
            rootCert = null;
            throw new IllegalStateException("Kök CA yüklenemedi: " + file, e);
        }
    }

    private ContentSigner rootSigner() throws OperatorCreationException {
        return new JcaContentSignerBuilder("SHA256withRSA").build(rootKey);
    }

    /** RFC 5280: pozitif, en fazla 20 bayt, tahmin edilemez. */
    private BigInteger serial() {
        return new BigInteger(127, random).add(BigInteger.ONE);
    }

    private static X509Certificate toCertificate(X509CertificateHolder holder) throws GeneralSecurityException {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }
}
