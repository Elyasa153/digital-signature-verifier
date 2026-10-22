package com.trustlayer.dsv.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.springframework.stereotype.Component;

import com.trustlayer.dsv.ca.CertificateAuthority;
import com.trustlayer.dsv.common.Certificates;
import com.trustlayer.dsv.common.SigningIdentity;

/**
 * PDF'e ayrık CMS imzası (ETSI.CAdES.detached) gömer ve doğrular (İP-4, FR-6, FR-7).
 * Doğrulama sırası {@link Verdict}'teki gibidir; ilk başarısız kontrol sonucu belirler.
 */
@Component
class PadesSignature implements PdfSigner, PdfVerifier {

    private final CertificateAuthority ca;

    PadesSignature(CertificateAuthority ca) {
        this.ca = ca;
    }

    // Sınır: PAdES-B-B'nin istediği signing-certificate-v2 özniteliği yok; Adobe bunsuz da doğrular.
    @Override
    public byte[] sign(byte[] pdf, SigningIdentity identity) {
        try (PDDocument doc = Loader.loadPDF(pdf); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
            signature.setName(Certificates.commonName(identity.certificate()));
            signature.setSignDate(Calendar.getInstance());
            // PDFBox imzalanacak bayt aralığını (ByteRange) verir, dönen CMS /Contents alanına yazılır.
            doc.addSignature(signature, content -> cms(content.readAllBytes(), identity));
            doc.saveIncremental(out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalArgumentException("PDF imzalanamadı", e);
        }
    }

    private static byte[] cms(byte[] content, SigningIdentity identity) throws IOException {
        try {
            String algorithm = "EC".equals(identity.privateKey().getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
                    .build(algorithm, identity.privateKey(), identity.certificate()));
            gen.addCertificates(new JcaCertStore(identity.chain()));
            // false: ayrık imza, belge baytları CMS'in içine kopyalanmaz.
            return gen.generate(new CMSProcessableByteArray(content), false).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new IOException("CMS imzası üretilemedi", e);
        }
    }

    @Override
    public VerificationResult verify(byte[] pdf) {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            List<PDSignature> signatures = doc.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                return new VerificationResult(Verdict.UNSIGNED, null, null, "Belgede elektronik imza bulunamadı.");
            }
            // Sınır: tek imza varsayılır (sistem belgeyi bir kez imzalar).
            return check(signatures.get(0), pdf);
        } catch (IOException e) {
            return new VerificationResult(Verdict.UNSIGNED, null, null, "Dosya PDF olarak okunamadı.");
        }
    }

    private VerificationResult check(PDSignature signature, byte[] pdf) {
        // 2. Belge değişmiş mi?
        int[] range = signature.getByteRange();
        if (range.length != 4 || range[0] != 0 || range[1] > range[2] || (long) range[2] + range[3] != pdf.length) {
            return modified("İmzadan sonra dosyaya veri eklenmiş ya da imza alanı bozulmuş.");
        }
        X509Certificate cert;
        Instant signedAt;
        try {
            // /Contents sabit boyutlu ayrılır, sonu sıfır dolgulu; yalnız ilk ASN.1 nesnesi CMS'tir.
            ContentInfo info = ContentInfo.getInstance(new ASN1InputStream(signature.getContents()).readObject());
            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signature.getSignedContent(pdf)), info);
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
            if (matches.isEmpty()) {
                return modified("İmzalayanın sertifikası imzada yok.");
            }
            cert = new JcaX509CertificateConverter().getCertificate(matches.iterator().next());
            // Özet (SHA-256) + imza: imzalanan bayt aralığında tek bayt değişse burada düşer.
            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {
                return modified("Belge imzalandıktan sonra değiştirilmiş.");
            }
            signedAt = signingTime(signer, signature);
        } catch (Exception e) {
            return modified("Belge imzalandıktan sonra değiştirilmiş.");
        }
        String signerName = Certificates.commonName(cert);

        // 3. İmzalayana güvenilir mi?
        X509Certificate root = ca.rootCertificate();
        try {
            if (!cert.getIssuerX500Principal().equals(root.getSubjectX500Principal())) {
                throw new GeneralSecurityException("başka bir kökten");
            }
            cert.verify(root.getPublicKey());
            cert.checkValidity(Date.from(signedAt == null ? Instant.now() : signedAt));
            boolean[] usage = cert.getKeyUsage();
            if (usage != null && !usage[0]) {
                throw new GeneralSecurityException("imza için verilmemiş");
            }
        } catch (GeneralSecurityException e) {
            return new VerificationResult(Verdict.UNTRUSTED, signerName, signedAt,
                    "İmza sağlam ama imzalayanın sertifikası tanınan kök CA'ya bağlanmıyor.");
        }

        // 4. Sertifika iptal edilmiş mi?
        if (ca.currentCrl().isRevoked(cert)) {
            return new VerificationResult(Verdict.REVOKED, signerName, signedAt,
                    "İmzalayan kurumun sertifikası iptal edilmiş.");
        }
        return new VerificationResult(Verdict.VALID, signerName, signedAt,
                "Belge değiştirilmemiş ve tanınan bir kurum tarafından imzalanmış.");
    }

    /** CMS'teki imzalı signing-time; yoksa PDF imza sözlüğündeki /M (K8: zaman damgası değil). */
    private static Instant signingTime(SignerInformation signer, PDSignature signature) {
        AttributeTable attrs = signer.getSignedAttributes();
        Attribute time = attrs == null ? null : attrs.get(CMSAttributes.signingTime);
        if (time != null) {
            return Time.getInstance(time.getAttrValues().getObjectAt(0)).getDate().toInstant();
        }
        return signature.getSignDate() == null ? null : signature.getSignDate().toInstant();
    }

    private static VerificationResult modified(String detail) {
        return new VerificationResult(Verdict.MODIFIED, null, null, detail);
    }
}
