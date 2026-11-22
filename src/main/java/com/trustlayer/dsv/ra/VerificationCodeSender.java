package com.trustlayer.dsv.ra;

/** Kurum başvurusu e-posta doğrulama kodu gönderici (SMTP veya demo günlük). */
public interface VerificationCodeSender {

    void send(String email, String institutionId, String code);
}
