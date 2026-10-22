package com.trustlayer.dsv.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.trustlayer.dsv.ca.CertificateAuthority;
import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.common.SigningIdentity;
import com.trustlayer.dsv.institution.InstitutionRegistry;

@SpringBootTest
class PadesSignatureTest {

    @TempDir
    static Path runtime;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("dsv.runtime-dir", runtime::toString);
        r.add("dsv.keystore-password", () -> "test-parola");
    }

    @Autowired
    PdfSigner signer;

    @Autowired
    PdfVerifier verifier;

    @Autowired
    InstitutionRegistry registry;

    @Autowired
    CertificateAuthority ca;

    /** TS-05 / TS-06: üç algoritmayla imzalanan belge VALID; imzalayan sertifikadan okunur. */
    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void signedPdfIsValid(Algorithm algorithm) throws Exception {
        String id = "imza-" + algorithm.name().toLowerCase().replace('_', '-');
        registry.enroll(id, "Kurum " + algorithm, algorithm);
        byte[] signed = signer.sign(samplePdf(), registry.signingIdentity(id));

        VerificationResult r = verifier.verify(signed);
        assertEquals(Verdict.VALID, r.verdict(), r.detail());
        assertEquals("Kurum " + algorithm, r.signer());
        assertNotNull(r.signedAt());
        try (PDDocument doc = Loader.loadPDF(signed)) {
            PDSignature sig = doc.getSignatureDictionaries().get(0);
            assertEquals(PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName(), sig.getSubFilter());
        }
    }

    /** TS-07: imzalanan aralıkta, içerik akışında tek bayt değişirse MODIFIED (özet kontrolü). */
    @Test
    void singleByteChangeInContentIsModified() throws Exception {
        byte[] signed = signedByDemo();
        byte[] tampered = signed.clone();
        int i = indexOf(signed, "stream".getBytes(StandardCharsets.US_ASCII)) + 20;
        tampered[i] ^= 0x01;

        VerificationResult r = verifier.verify(tampered);
        assertEquals(Verdict.MODIFIED, r.verdict(), r.detail());
    }

    /** TS-08B: imzadan sonra dosyanın sonuna veri eklenirse MODIFIED (ByteRange kapsamı). */
    @Test
    void appendedBytesAreModified() throws Exception {
        byte[] signed = signedByDemo();
        byte[] appended = Arrays.copyOf(signed, signed.length + 16);
        System.arraycopy("%eklenmis-veri%\n".getBytes(StandardCharsets.US_ASCII), 0, appended, signed.length, 16);

        assertEquals(Verdict.MODIFIED, verifier.verify(appended).verdict());
    }

    /** İmzadan sonra PDF'e yeni sürüm (sayfa) eklenmesi de MODIFIED. */
    @Test
    void incrementalUpdateAfterSigningIsModified() throws Exception {
        byte[] signed = signedByDemo();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (PDDocument doc = Loader.loadPDF(signed)) {
            doc.addPage(new PDPage());
            doc.getPages().getCOSObject().setNeedToBeUpdated(true);
            doc.saveIncremental(out);
        }
        assertEquals(Verdict.MODIFIED, verifier.verify(out.toByteArray()).verdict());
    }

    /** İmzanın kendisi (/Contents) bozulursa MODIFIED. */
    @Test
    void corruptedSignatureIsModified() throws Exception {
        byte[] signed = signedByDemo();
        int[] range;
        try (PDDocument doc = Loader.loadPDF(signed)) {
            range = doc.getSignatureDictionaries().get(0).getByteRange();
        }
        byte[] tampered = signed.clone();
        int i = range[1] + 200; // /Contents <...> onaltılık imza alanının içi
        tampered[i] = (byte) (tampered[i] == '0' ? '1' : '0');

        assertEquals(Verdict.MODIFIED, verifier.verify(tampered).verdict());
    }

    /** Bizim köke bağlanmayan imza UNTRUSTED; kökün adını taklit eden sahte kök de. */
    @Test
    void signatureFromForeignRootIsUntrusted() throws Exception {
        KeyPair pair = ec();
        String rootName = ca.rootCertificate().getSubjectX500Principal().getName();
        for (String issuer : List.of("CN=Sahte Kök, C=TR", rootName)) {
            X509Certificate cert = certificate("CN=Sahte Kurum, C=TR", issuer, pair);
            byte[] signed = signer.sign(samplePdf(), new SigningIdentity("sahte", pair.getPrivate(), List.of(cert)));

            VerificationResult r = verifier.verify(signed);
            assertEquals(Verdict.UNTRUSTED, r.verdict(), issuer);
            assertEquals("Sahte Kurum", r.signer());
        }
    }

    /** TS-08: sertifikası iptal edilen kurumun önceden imzaladığı belge REVOKED. */
    @Test
    void revokedCertificateIsRevoked() throws Exception {
        registry.enroll("iptal-kurum", "İptal Kurumu", Algorithm.ECDSA_P256);
        SigningIdentity identity = registry.signingIdentity("iptal-kurum");
        byte[] signed = signer.sign(samplePdf(), identity);
        assertEquals(Verdict.VALID, verifier.verify(signed).verdict());

        ca.revoke(identity.certificate().getSerialNumber());
        assertEquals(Verdict.REVOKED, verifier.verify(signed).verdict());
    }

    @Test
    void unsignedOrNotPdfIsUnsigned() throws Exception {
        assertEquals(Verdict.UNSIGNED, verifier.verify(samplePdf()).verdict());
        assertEquals(Verdict.UNSIGNED, verifier.verify("pdf değil".getBytes(StandardCharsets.UTF_8)).verdict());
        assertEquals(Verdict.UNSIGNED, verifier.verify(new byte[0]).verdict());
    }

    private byte[] signedByDemo() throws Exception {
        return signer.sign(samplePdf(), registry.signingIdentity("ornek-hastane"));
    }

    static byte[] samplePdf() throws Exception {
        try (PDDocument doc = new PDDocument(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            PDPage page = new PDPage();
            doc.addPage(page);
            try (var cs = new org.apache.pdfbox.pdmodel.PDPageContentStream(doc, page)) {
                cs.addRect(50, 50, 200, 200);
                cs.fill();
            }
            doc.save(out);
            return out.toByteArray();
        }
    }

    static KeyPair ec() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    /** {@code issuer} adını taşıyan ama kendi anahtarıyla imzalanmış sertifika. */
    static X509Certificate certificate(String subject, String issuer, KeyPair pair) throws Exception {
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(30))),
                new X500Name(subject), pair.getPublic());
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
    }

    static int indexOf(byte[] data, byte[] pattern) {
        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        throw new IllegalArgumentException("bulunamadı");
    }
}
