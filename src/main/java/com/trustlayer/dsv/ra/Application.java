package com.trustlayer.dsv.ra;

import java.time.Instant;

import com.trustlayer.dsv.common.Algorithm;

/** Kurum başvurusu (K11). {@code id} onaydan sonra kurum kimliği ve operatör kullanıcı adı olur. */
public record Application(String id, String displayName, Algorithm algorithm, String contactName, String email,
        Status status, Instant createdAt, String note) {

    public enum Status {
        /** E-postaya gönderilen tek kullanımlık kod bekleniyor (bant dışı doğrulama). */
        KOD_BEKLIYOR,
        /** Kurum e-postasını kontrol ettiğini kanıtladı; CA yöneticisinin kararı bekleniyor. */
        ONAY_BEKLIYOR,
        ONAYLANDI,
        REDDEDILDI
    }

    Application with(Status newStatus, String newNote) {
        return new Application(id, displayName, algorithm, contactName, email, newStatus, createdAt, newNote);
    }
}
