package com.trustlayer.dsv.ra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import jakarta.mail.internet.MimeMessage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/** Hafta 7: SMTP ayarlıyken sahte posta göndericiyle e-posta, ayarsızken günlük (demo modu) testi. */
@ExtendWith(OutputCaptureExtension.class)
class MailVerificationCodeSenderTest {

    @Test
    void sendsEmailWhenSmtpHostIsConfigured() {
        FakeMailSender fake = new FakeMailSender();
        var sender = new MailVerificationCodeSender(fake, "smtp.example.com", "noreply@trustlayer.local");

        sender.send("yetkili@ornek.edu.tr", "ornek-uni", "482910");

        assertEquals(1, fake.sent.size());
        SimpleMailMessage msg = fake.sent.get(0);
        assertEquals("noreply@trustlayer.local", msg.getFrom());
        assertEquals("yetkili@ornek.edu.tr", msg.getTo()[0]);
        assertTrue(msg.getText().contains("482910"));
        assertTrue(msg.getText().contains("ornek-uni"));
    }

    @Test
    void logsCodeInDemoModeWhenSmtpHostIsNotConfigured(CapturedOutput log) {
        FakeMailSender fake = new FakeMailSender();
        var sender = new MailVerificationCodeSender(fake, "", "noreply@trustlayer.local");

        sender.send("yetkili@ornek.edu.tr", "ornek-uni", "654321");

        assertTrue(fake.sent.isEmpty(), "Demo modunda SMTP çağrılmamalı");
        assertTrue(log.getOut().contains("doğrulama kodu: 654321 (başvuru ornek-uni)"), log.getOut());
    }

    /** Gerçek SMTP bağlantısı kurmadan gönderilen mesajları bellekte toplayan sahte gönderici. */
    static class FakeMailSender implements JavaMailSender {
        final List<SimpleMailMessage> sent = new ArrayList<>();

        @Override
        public void send(SimpleMailMessage simpleMessage) {
            sent.add(simpleMessage);
        }

        @Override
        public void send(SimpleMailMessage... simpleMessages) {
            for (SimpleMailMessage m : simpleMessages) {
                sent.add(m);
            }
        }

        @Override
        public MimeMessage createMimeMessage() {
            throw new UnsupportedOperationException();
        }

        @Override
        public MimeMessage createMimeMessage(InputStream contentStream) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void send(MimeMessage mimeMessage) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void send(MimeMessage... mimeMessages) {
            throw new UnsupportedOperationException();
        }
    }
}
