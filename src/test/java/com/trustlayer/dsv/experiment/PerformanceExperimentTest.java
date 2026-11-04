package com.trustlayer.dsv.experiment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.signature.Verdict;

@SpringBootTest
class PerformanceExperimentTest {

    @TempDir
    static Path runtime;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("dsv.runtime-dir", runtime::toString);
        r.add("dsv.keystore-password", () -> "test-parola");
    }

    @Autowired
    PerformanceExperiment experiment;

    /** Küçük belgeyle tam deney: 3 algoritma × 1 boyut × 30 tekrar, hepsi VALID, iki CSV yazılır. */
    @Test
    void runsAllCombinationsAndWritesCsv(@TempDir Path out) throws Exception {
        var all = experiment.run(List.of(4 * 1024), out);

        assertEquals(3 * PerformanceExperiment.REPEATS, all.size());
        assertTrue(all.stream().allMatch(m -> m.verdict() == Verdict.VALID));
        assertEquals(1 + all.size(), Files.readAllLines(out.resolve("olcumler.csv")).size());
        List<String> summary = Files.readAllLines(out.resolve("ozet.csv"));
        assertEquals(1 + Algorithm.values().length, summary.size());
        assertTrue(summary.get(1).endsWith(";0"), summary.get(1)); // yanlış red yok
    }

    /** İmza değeri: RSA-2048 256 bayt, RSA-3072 384 bayt, ECDSA P-256 DER olarak 70-72 bayt. */
    @Test
    void signatureValueSizeMatchesAlgorithm(@TempDir Path out) {
        var all = experiment.run(List.of(2 * 1024), out);
        for (var m : all) {
            int size = m.signatureValueBytes();
            switch (m.algorithm()) {
                case RSA_2048 -> assertEquals(256, size);
                case RSA_3072 -> assertEquals(384, size);
                case ECDSA_P256 -> assertTrue(size >= 68 && size <= 72, "ECDSA " + size);
            }
            assertTrue(m.cmsBytes() > size, "CMS sertifika zincirini de taşır");
        }
    }

    @Test
    void pdfIsCloseToTargetSize() {
        for (int target : List.of(100 * 1024, 1024 * 1024)) {
            int size = PerformanceExperiment.pdfOfSize(target).length;
            assertTrue(Math.abs(size - target) < 2048, target + " → " + size);
        }
    }

    /** 1..30: ortalama 15.5, ss √77.5, GA yarı genişliği 2.045·ss/√30. */
    @Test
    void summaryStatistics() {
        double[] xs = IntStream.rangeClosed(1, 30).asDoubleStream().toArray();
        double[] s = PerformanceExperiment.summarize(xs);
        assertEquals(15.5, s[0], 1e-9);
        assertEquals(Math.sqrt(77.5), s[1], 1e-9);
        assertEquals(2.045 * Math.sqrt(77.5) / Math.sqrt(30), s[2], 1e-9);
    }
}
