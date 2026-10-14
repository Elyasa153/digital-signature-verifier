package com.trustlayer.dsv.signature;

/**
 * Doğrulama sonucu. Kontroller bu sırayla yapılır, ilk başarısız olan sonucu belirler:
 * imza var mı → belge değişmiş mi → zincir kök CA'ya çıkıyor mu → sertifika iptal mi.
 */
public enum Verdict {
    /** PDF'te imza yok ya da dosya PDF değil. */
    UNSIGNED,
    /** İmzadan sonra içerik değişmiş ya da imza matematiksel olarak tutmuyor. */
    MODIFIED,
    /** İmza sağlam ama bizim kök CA'mıza zincirlenmiyor. */
    UNTRUSTED,
    /** İmza sağlam, zincir doğru, ama kurum sertifikası CRL'de. */
    REVOKED,
    VALID
}
