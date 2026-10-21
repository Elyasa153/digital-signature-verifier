package com.trustlayer.dsv.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CsvRecordSourceTest {

    @TempDir
    Path dir;

    CsvRecordSource source;

    @BeforeEach
    void setUp() throws IOException {
        Files.createDirectories(dir.resolve("kurum"));
        Files.writeString(dir.resolve("kurum/belge.csv"), """
                ﻿no;ad;bolum
                1;Ayşe Yıldırım;Bilgisayar
                2;Mehmet Çağlar;Elektrik
                """);
        Files.writeString(dir.resolve("kurum/dersler.csv"), """
                no;kod
                1;BMÜ-101
                2;MAT-101
                1;BMÜ-102
                """);
        source = new CsvRecordSource(dir);
    }

    @Test
    void findsRecordByFirstColumn() {
        assertEquals(Map.of("no", "2", "ad", "Mehmet Çağlar", "bolum", "Elektrik"),
                source.find("kurum", "belge", "2").orElseThrow());
    }

    @Test
    void missingRecordOrFileIsEmpty() {
        assertTrue(source.find("kurum", "belge", "99").isEmpty());
        assertTrue(source.find("kurum", "olmayan", "1").isEmpty());
        assertTrue(source.find("baska-kurum", "belge", "1").isEmpty());
    }

    @Test
    void findRowsReturnsAllRowsOfRecordInOrder() {
        var rows = source.findRows("kurum", "dersler", "1");
        assertEquals(2, rows.size());
        assertEquals("BMÜ-101", rows.get(0).get("kod"));
        assertEquals("BMÜ-102", rows.get(1).get("kod"));
    }

    @Test
    void malformedLineIsRejectedWithLineNumber() throws IOException {
        Files.writeString(dir.resolve("kurum/bozuk.csv"), "no;ad\n1;Ayşe\n2;Mehmet;fazla\n");
        var e = assertThrows(IllegalArgumentException.class, () -> source.find("kurum", "bozuk", "2"));
        assertTrue(e.getMessage().contains("satır 3"), e.getMessage());
    }

    @Test
    void pathTraversalIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> source.find("../kurum", "belge", "1"));
        assertThrows(IllegalArgumentException.class, () -> source.find("kurum", "..\\belge", "1"));
        assertThrows(IllegalArgumentException.class, () -> source.find("Kurum", "belge", "1"));
    }
}
