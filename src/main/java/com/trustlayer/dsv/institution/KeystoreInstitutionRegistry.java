package com.trustlayer.dsv.institution;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.trustlayer.dsv.ca.CertificateAuthority;
import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.common.Certificates;
import com.trustlayer.dsv.common.SigningIdentity;

/**
 * Kurum anahtarları {@code <runtime>/institutions/<id>.p12} içinde, parolalı (K5).
 * Gizli anahtar bu sınıftan çıkmaz; CA yalnızca CSR görür (K4).
 */
@Component
class KeystoreInstitutionRegistry implements InstitutionRegistry {

    private static final Pattern ID = Pattern.compile("[a-z0-9-]+");
    private static final String ALIAS = "kurum";

    private final CertificateAuthority ca;
    private final Path dir;
    private final char[] password;

    KeystoreInstitutionRegistry(CertificateAuthority ca, @Value("${dsv.runtime-dir}") Path runtimeDir,
            @Value("${dsv.keystore-password}") String password) {
        this.ca = ca;
        this.dir = runtimeDir.resolve("institutions");
        this.password = password.toCharArray();
    }

    @Override
    public synchronized Institution enroll(String id, String displayName, Algorithm algorithm) {
        Path file = file(id);
        if (Files.exists(file)) {
            throw new IllegalArgumentException("Kurum zaten kayıtlı: " + id);
        }
        try {
            KeyPair pair = generate(algorithm);
            X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.C, "TR").addRDN(BCStyle.O, displayName).addRDN(BCStyle.CN, displayName).build();
            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic())
                    .build(new JcaContentSignerBuilder(signatureAlgorithm(algorithm)).build(pair.getPrivate()));

            X509Certificate cert = ca.issue(csr, id);

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry(ALIAS, pair.getPrivate(), password, new Certificate[] { cert, ca.rootCertificate() });
            Files.createDirectories(dir);
            try (OutputStream out = Files.newOutputStream(file)) {
                ks.store(out, password);
            }
            return new Institution(id, displayName, algorithm);
        } catch (GeneralSecurityException | OperatorCreationException e) {
            throw new IllegalStateException("Kurum kaydedilemedi: " + id, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public synchronized SigningIdentity signingIdentity(String institutionId) {
        KeyStore ks = load(institutionId);
        try {
            PrivateKey key = (PrivateKey) ks.getKey(ALIAS, password);
            List<X509Certificate> chain = Arrays.stream(ks.getCertificateChain(ALIAS))
                    .map(X509Certificate.class::cast).toList();
            return new SigningIdentity(institutionId, key, chain);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Kurum anahtarı açılamadı: " + institutionId, e);
        }
    }

    @Override
    public synchronized List<Institution> all() {
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        List<Institution> result = new ArrayList<>();
        try (Stream<Path> files = Files.list(dir)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".p12")).sorted().toList()) {
                String id = f.getFileName().toString().replace(".p12", "");
                X509Certificate cert = signingIdentity(id).certificate();
                result.add(new Institution(id, Certificates.commonName(cert), algorithmOf(cert)));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return result;
    }

    private KeyStore load(String institutionId) {
        Path file = file(institutionId);
        if (!Files.exists(file)) {
            throw new IllegalArgumentException("Kurum kayıtlı değil: " + institutionId);
        }
        try (InputStream in = Files.newInputStream(file)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, password);
            return ks;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Anahtar deposu açılamadı (parola?): " + institutionId, e);
        }
    }

    /** {@code id} dosya adına girer; {@code ../} gibi değerler buradan geçemez. */
    private Path file(String id) {
        if (id == null || !ID.matcher(id).matches()) {
            throw new IllegalArgumentException("Geçersiz kurum kimliği: " + id);
        }
        if (password.length == 0) {
            throw new IllegalStateException("DSV_KEYSTORE_PASSWORD ortam değişkeni ayarlanmamış");
        }
        return dir.resolve(id + ".p12");
    }

    private static KeyPair generate(Algorithm algorithm) throws GeneralSecurityException {
        KeyPairGenerator gen;
        switch (algorithm) {
            case RSA_2048 -> {
                gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
            }
            case RSA_3072 -> {
                gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(3072);
            }
            case ECDSA_P256 -> {
                gen = KeyPairGenerator.getInstance("EC");
                gen.initialize(new ECGenParameterSpec("secp256r1"));
            }
            default -> throw new IllegalArgumentException("Desteklenmeyen algoritma: " + algorithm);
        }
        return gen.generateKeyPair();
    }

    private static String signatureAlgorithm(Algorithm algorithm) {
        return algorithm == Algorithm.ECDSA_P256 ? "SHA256withECDSA" : "SHA256withRSA";
    }

    private static Algorithm algorithmOf(X509Certificate cert) {
        if (cert.getPublicKey() instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength() > 2048 ? Algorithm.RSA_3072 : Algorithm.RSA_2048;
        }
        return Algorithm.ECDSA_P256;
    }
}
