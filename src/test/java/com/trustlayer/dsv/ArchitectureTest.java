package com.trustlayer.dsv;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/** Modüller yalnız izin verilen paketleri import edebilir. */
class ArchitectureTest {

    private static final Path ROOT = Path.of("src/main/java/com/trustlayer/dsv");
    private static final Pattern IMPORT = Pattern.compile("^import\\s+(?:static\\s+)?com\\.trustlayer\\.dsv\\.(\\w+)\\.", Pattern.MULTILINE);

    private static final Map<String, Set<String>> ALLOWED = Map.of(
            "common", Set.of(),
            "ca", Set.of("common"),
            "institution", Set.of("ca", "common"),
            "document", Set.of("common"),
            "signature", Set.of("ca", "common"),
            "experiment", Set.of("signature", "institution", "common"));
    // web her şeyi kullanabilir, listede yok.

    @Test
    void modulesOnlyDependOnAllowedModules() throws IOException {
        List<String> violations = new ArrayList<>();
        for (var entry : ALLOWED.entrySet()) {
            Path dir = ROOT.resolve(entry.getKey());
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(dir)) {
                for (Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                    Matcher m = IMPORT.matcher(Files.readString(file));
                    while (m.find()) {
                        String target = m.group(1);
                        if (!target.equals(entry.getKey()) && !entry.getValue().contains(target)) {
                            violations.add(ROOT.relativize(file) + " → " + target);
                        }
                    }
                }
            }
        }
        assertTrue(violations.isEmpty(), "İzin verilmeyen bağımlılık: " + violations);
    }
}
