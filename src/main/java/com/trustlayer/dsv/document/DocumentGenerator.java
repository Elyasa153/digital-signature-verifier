package com.trustlayer.dsv.document;

/**
 * Şablon + kayıt → imzasız PDF (İP-3). İmza ve kurum anahtarından habersizdir.
 */
public interface DocumentGenerator {

    /**
     * Kurumun {@code documentType} şablonunu {@code recordId} kaydıyla doldurur, doğrulama QR'ı ekler (FR-3..FR-5).
     *
     * @throws IllegalArgumentException kayıt yoksa ya da şablonun istediği bir alan eksikse
     */
    GeneratedDocument generate(String institutionId, String documentType, String recordId);
}
