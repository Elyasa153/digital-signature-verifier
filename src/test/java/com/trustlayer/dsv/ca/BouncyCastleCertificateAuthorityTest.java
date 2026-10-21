package com.trustlayer.dsv.ca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BouncyCastleCertificateAuthorityTest {

    static final String CRL_URL = "http://localhost:8080/crl";

    @TempDir
    static Path runtime;

    static BouncyCastleCertificateAuthority ca;

    @BeforeAll
    static void setUp() {
        ca = new BouncyCastleCertificateAuthority(runtime, "test-parola", CRL_URL);
    }

    /** TS-01: kök CA kendinden imzalı, CA=true, yalnız sertifika ve CRL imzalar. */
    @Test
    void rootIsSelfSignedCa() throws Exception {
        X509Certificate root = ca.rootCertificate();
        root.verify(root.getPublicKey());
        assertEquals(Integer.MAX_VALUE, root.getBasicConstraints());
        boolean[] usage = root.getKeyUsage();
        assertTrue(usage[5] && usage[6], "keyCertSign + cRLSign");
        assertFalse(usage[0], "kök CA belge imzalamaz");
    }

    /** TS-02: CSR'dan verilen kurum sertifikası köke zincirlenir; CA değil, yalnız imza için. */
    @Test
    void issuesInstitutionCertificateFromCsr() throws Exception {
        KeyPair pair = ec();
        X509Certificate cert = ca.issue(csr("CN=Örnek Hastanesi, C=TR", pair, pair), "ornek-hastane");

        cert.verify(ca.rootCertificate().getPublicKey());
        assertEquals(ca.rootCertificate().getSubjectX500Principal(), cert.getIssuerX500Principal());
        assertEquals(pair.getPublic(), cert.getPublicKey());
        assertEquals(-1, cert.getBasicConstraints(), "CA=false");
        boolean[] usage = cert.getKeyUsage();
        assertTrue(usage[0] && usage[1], "digitalSignature + nonRepudiation");
        assertFalse(usage[2], "keyEncipherment yok");
        assertNull(cert.getExtensionValue(Extension.extendedKeyUsage.getId()), "EKU yok");
        assertTrue(new String(cert.getExtensionValue(Extension.cRLDistributionPoints.getId())).contains(CRL_URL));
    }

    /** K4: CSR, içindeki açık anahtarın sahibi tarafından imzalanmamışsa reddedilir. */
    @Test
    void rejectsCsrSignedByAnotherKey() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> ca.issue(csr("CN=Sahte, C=TR", ec(), ec()), "sahte"));
    }

    /** TS-03 + TS-04: CRL kök imzalı; iptal edilen seri listede, diğeri değil. */
    @Test
    void revokedSerialAppearsInSignedCrl() throws Exception {
        KeyPair a = ec();
        KeyPair b = ec();
        X509Certificate revoked = ca.issue(csr("CN=A, C=TR", a, a), "a");
        X509Certificate active = ca.issue(csr("CN=B, C=TR", b, b), "b");

        ca.revoke(revoked.getSerialNumber());
        X509CRL crl = ca.currentCrl();

        crl.verify(ca.rootCertificate().getPublicKey());
        assertTrue(crl.isRevoked(revoked));
        assertFalse(crl.isRevoked(active));
    }

    /** Kök anahtar diskte kalır: yeniden başlatınca aynı kök, aynı iptaller. */
    @Test
    void rootAndRevocationsSurviveRestart() throws Exception {
        KeyPair pair = ec();
        X509Certificate cert = ca.issue(csr("CN=C, C=TR", pair, pair), "c");
        ca.revoke(cert.getSerialNumber());

        var restarted = new BouncyCastleCertificateAuthority(runtime, "test-parola", CRL_URL);
        assertArrayEquals(ca.rootCertificate().getEncoded(), restarted.rootCertificate().getEncoded());
        assertTrue(restarted.currentCrl().isRevoked(cert));
    }

    @Test
    void wrongOrMissingPasswordFails(@TempDir Path other) {
        ca.rootCertificate(); // root.p12 diskte olsun
        assertThrows(IllegalStateException.class, () -> new BouncyCastleCertificateAuthority(other, "", CRL_URL).rootCertificate());
        assertThrows(IllegalStateException.class,
                () -> new BouncyCastleCertificateAuthority(runtime, "yanlis", CRL_URL).rootCertificate());
    }

    static KeyPair ec() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    /** {@code subjectKey}'in açık anahtarı için, {@code signingKey} ile imzalı CSR. */
    static PKCS10CertificationRequest csr(String dn, KeyPair subjectKey, KeyPair signingKey) throws Exception {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name(dn), subjectKey.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(signingKey.getPrivate()));
    }
}
