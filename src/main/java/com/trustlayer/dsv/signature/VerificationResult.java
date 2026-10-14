package com.trustlayer.dsv.signature;

import java.time.Instant;

/**
 * @param signer   imzalayan kurumun sertifikadaki adı; {@link Verdict#UNSIGNED} ise null
 * @param signedAt imzadaki zaman; {@link Verdict#UNSIGNED} ise null
 * @param detail   kullanıcıya gösterilecek kısa açıklama
 */
public record VerificationResult(Verdict verdict, String signer, Instant signedAt, String detail) {
}
