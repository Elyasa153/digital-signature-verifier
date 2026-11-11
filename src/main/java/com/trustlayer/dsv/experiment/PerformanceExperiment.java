package com.trustlayer.dsv.experiment;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdfwriter.compress.CompressParameters;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.springframework.stereotype.Component;

import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.common.SigningIdentity;
import com.trustlayer.dsv.institution.Institution;
import com.trustlayer.dsv.institution.InstitutionRegistry;
import com.trustlayer.dsv.signature.PdfSigner;
import com.trustlayer.dsv.signature.PdfVerifier;
import com.trustlayer.dsv.signature.Verdict;

/**
 * Başarım deneyi (FR-10): 3 algoritma × belge boyutları × 30 tekrar.
 * Ölçülen: imzalama süresi, doğrulama süresi, CMS boyutu (sertifika zinciri dahil) ve yalnız imza değerinin boyutu.
 * Her ölçümde sağlam belgenin VALID dönüp dönmediği de yazılır: yanlış red oranı (FR-7, hedef %0).
 */
@Component
public class PerformanceExperiment {

    /** %95 güven aralığı için t(0.975, sd=29); tekrar sayısı değişirse bu da değişmeli. */
    static final int REPEATS = 30;
    static final double T_95 = 2.045;
    /** JIT ısınması: her kombinasyonda ölçülmeyen ilk turlar. 5 tur ilk algoritmayı yavaş ölçtü (11-11). */
    static final int WARMUP = 30;

    private final PdfSigner signer;
    private final PdfVerifier verifier;
    private final InstitutionRegistry registry;

    PerformanceExperiment(PdfSigner signer, PdfVerifier verifier, InstitutionRegistry registry) {
        this.signer = signer;
        this.verifier = verifier;
        this.registry = registry;
    }

    /** Ölçümleri {@code outDir/olcumler.csv}, özeti {@code outDir/ozet.csv} dosyasına yazar. */
    public List<Measurement> run(List<Integer> sizesInBytes, Path outDir) {
        List<Measurement> all = new ArrayList<>();
        for (Algorithm algorithm : Algorithm.values()) {
            SigningIdentity identity = identity(algorithm);
            for (int size : sizesInBytes) {
                byte[] pdf = pdfOfSize(size);
                for (int i = 0; i < WARMUP; i++) {
                    measure(algorithm, pdf, identity, 0);
                }
                for (int i = 1; i <= REPEATS; i++) {
                    all.add(measure(algorithm, pdf, identity, i));
                }
            }
        }
        write(outDir, all);
        return all;
    }

    private Measurement measure(Algorithm algorithm, byte[] pdf, SigningIdentity identity, int repeat) {
        long t0 = System.nanoTime();
        byte[] signed = signer.sign(pdf, identity);
        long t1 = System.nanoTime();
        Verdict verdict = verifier.verify(signed).verdict();
        long t2 = System.nanoTime();
        int[] sizes = signatureSizes(signed);
        return new Measurement(algorithm, pdf.length, repeat, (t1 - t0) / 1e6, (t2 - t1) / 1e6,
                sizes[0], sizes[1], verdict);
    }

    /** Her algoritma için ayrı deney kurumu; runtime klasöründe varsa yeniden kaydedilmez. */
    private SigningIdentity identity(Algorithm algorithm) {
        String id = "deney-" + algorithm.name().toLowerCase(Locale.ROOT).replace('_', '-');
        Set<String> enrolled = registry.all().stream().map(Institution::id).collect(Collectors.toSet());
        if (!enrolled.contains(id)) {
            registry.enroll(id, "Deney Kurumu " + algorithm, algorithm);
        }
        return registry.signingIdentity(id);
    }

    /**
     * Tek sayfalık PDF + sıkıştırılmamış rastgele bayt akışı; dosya boyutu hedefe birkaç yüz bayt yakın.
     * Akış sayfa sözlüğüne bağlı, imza onu da kapsar. Tohum sabit: her çalıştırmada aynı belgeler.
     */
    static byte[] pdfOfSize(int targetBytes) {
        try (PDDocument doc = new PDDocument(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            PDPage page = new PDPage();
            doc.addPage(page);
            byte[] filler = new byte[Math.max(0, targetBytes - 1000)];
            new Random(targetBytes).nextBytes(filler);
            COSStream stream = doc.getDocument().createCOSStream();
            try (OutputStream raw = stream.createRawOutputStream()) {
                raw.write(filler);
            }
            page.getCOSObject().setItem(COSName.getPDFName("DeneyDolgu"), stream);
            doc.save(out, CompressParameters.NO_COMPRESSION);
            return out.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** [CMS'in DER boyutu, imza değerinin boyutu]; /Contents'in sıfır dolgusu sayılmaz. */
    static int[] signatureSizes(byte[] signedPdf) {
        try (PDDocument doc = Loader.loadPDF(signedPdf);
                ASN1InputStream in = new ASN1InputStream(doc.getSignatureDictionaries().get(0).getContents())) {
            ContentInfo info = ContentInfo.getInstance(in.readObject());
            SignedData data = SignedData.getInstance(info.getContent());
            SignerInfo signerInfo = SignerInfo.getInstance(data.getSignerInfos().getObjectAt(0));
            return new int[] { info.getEncoded(ASN1Encoding.DER).length, signerInfo.getEncryptedDigest().getOctets().length };
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** [ortalama, örneklem standart sapması, %95 GA yarı genişliği]. */
    static double[] summarize(double[] xs) {
        double mean = 0;
        for (double x : xs) {
            mean += x;
        }
        mean /= xs.length;
        double ss = 0;
        for (double x : xs) {
            ss += (x - mean) * (x - mean);
        }
        double sd = Math.sqrt(ss / (xs.length - 1));
        return new double[] { mean, sd, T_95 * sd / Math.sqrt(xs.length) };
    }

    private static void write(Path outDir, List<Measurement> all) {
        List<String> raw = new ArrayList<>();
        raw.add("algoritma;belge_bayt;tekrar;imzalama_ms;dogrulama_ms;cms_bayt;imza_degeri_bayt;sonuc");
        for (Measurement m : all) {
            raw.add(String.format(Locale.ROOT, "%s;%d;%d;%.3f;%.3f;%d;%d;%s", m.algorithm(), m.documentBytes(),
                    m.repeat(), m.signMs(), m.verifyMs(), m.cmsBytes(), m.signatureValueBytes(), m.verdict()));
        }

        List<String> summary = new ArrayList<>();
        summary.add("algoritma;belge_bayt;n;imzalama_ort_ms;imzalama_ss_ms;imzalama_ga95_ms;"
                + "dogrulama_ort_ms;dogrulama_ss_ms;dogrulama_ga95_ms;cms_bayt_ort;imza_degeri_bayt_ort;yanlis_red");
        all.stream().collect(Collectors.groupingBy(m -> m.algorithm() + ";" + m.documentBytes(),
                LinkedHashMap::new, Collectors.toList())).forEach((key, group) -> {
                    double[] sign = summarize(group.stream().mapToDouble(Measurement::signMs).toArray());
                    double[] verify = summarize(group.stream().mapToDouble(Measurement::verifyMs).toArray());
                    double cms = group.stream().mapToInt(Measurement::cmsBytes).average().orElse(0);
                    double value = group.stream().mapToInt(Measurement::signatureValueBytes).average().orElse(0);
                    long rejected = group.stream().filter(m -> m.verdict() != Verdict.VALID).count();
                    summary.add(String.format(Locale.ROOT, "%s;%d;%.3f;%.3f;%.3f;%.3f;%.3f;%.3f;%.1f;%.1f;%d",
                            key, group.size(), sign[0], sign[1], sign[2], verify[0], verify[1], verify[2],
                            cms, value, rejected));
                });
        try {
            Files.createDirectories(outDir);
            Files.write(outDir.resolve("olcumler.csv"), raw);
            Files.write(outDir.resolve("ozet.csv"), summary);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public record Measurement(Algorithm algorithm, int documentBytes, int repeat, double signMs, double verifyMs,
            int cmsBytes, int signatureValueBytes, Verdict verdict) {
    }
}
