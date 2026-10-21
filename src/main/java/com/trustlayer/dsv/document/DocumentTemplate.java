package com.trustlayer.dsv.document;

import java.util.List;

/**
 * {@code document-templates/<kurum>/<tür>.json} içeriği (K10). Metinlerdeki {@code {alan}} kayıttan doldurulur.
 *
 * @param intro   başlığın altındaki paragraf; boş olabilir
 * @param fields  "Etiket: değer" satırları
 * @param table   kayda bağlı satır tablosu (ör. transkriptteki dersler); boş olabilir
 * @param closing tablonun altındaki paragraf; boş olabilir
 */
record DocumentTemplate(String issuer, String title, String intro, List<Field> fields, Table table, String closing) {

    /** @param width sütun genişliği (pt); boşsa kalan genişlik eşit bölünür */
    record Field(String key, String label, Float width) {
    }

    /** @param source aynı kurum klasöründeki CSV'nin adı */
    record Table(String source, List<Field> columns) {
    }
}
