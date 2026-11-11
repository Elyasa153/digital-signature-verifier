package com.trustlayer.dsv.document;

/**
 * Paneldeki belge türü seçeneği.
 *
 * @param id   şablon dosyasının adı, ör. {@code saglik-raporu}
 * @param name kullanıcıya görünen ad
 * @param hint kayıt no alanının ipucu, ör. "Rapor No (ör. SR-2026-0101)"
 */
public record DocumentType(String id, String name, String hint) {
}
