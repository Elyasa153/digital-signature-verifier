package com.trustlayer.dsv.ra;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Denetim kaydı (K11 adım 5): kim, ne zaman, hangi kurum, hangi işlem. Yalnız sona eklenir, satır silinmez.
 * Satır: {@code <ISO zaman>\t<aktör>\t<işlem>\t<kurum>\t<ayrıntı>}.
 */
@Component
public class AuditLog {

    private final Path file;

    AuditLog(@Value("${dsv.runtime-dir}") Path runtimeDir) {
        this.file = runtimeDir.resolve("ra").resolve("denetim.log");
    }

    public record Entry(Instant at, String actor, String action, String institution, String detail) {
    }

    public synchronized void record(String actor, String action, String institution, String detail) {
        String line = String.join("\t", Instant.now().toString(), clean(actor), clean(action), clean(institution),
                clean(detail)) + "\n";
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, line, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** En yeni başta, en fazla {@code limit} kayıt. */
    public synchronized List<Entry> recent(int limit) {
        if (!Files.exists(file)) {
            return List.of();
        }
        try {
            List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
            Collections.reverse(lines); // Java 17: List.reversed() yok
            return lines.stream().limit(limit).map(l -> l.split("\t", 5))
                    .map(p -> new Entry(Instant.parse(p[0]), p[1], p[2], p[3], p.length > 4 ? p[4] : ""))
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Kullanıcı girdisi satır ya da sütun bölemesin. */
    private static String clean(String s) {
        return s == null ? "" : s.replaceAll("[\\t\\r\\n]", " ");
    }
}
