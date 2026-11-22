package com.trustlayer.dsv.ra;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/**
 * Doğrulama kodu gönderimi: spring.mail.host ayarlanmışsa Spring Mail (SMTP) ile e-posta gönderir;
 * ayarlanmamışsa demo modunda sunucu günlüğüne yazar.
 */
@Component
class MailVerificationCodeSender implements VerificationCodeSender {

    private static final Logger log = LoggerFactory.getLogger(MailVerificationCodeSender.class);

    private final JavaMailSender mailSender;
    private final String mailHost;
    private final String from;

    @Autowired
    MailVerificationCodeSender(
            ObjectProvider<JavaMailSender> mailSenderProvider,
            @Value("${spring.mail.host:}") String mailHost,
            @Value("${dsv.mail.from:noreply@trustlayer.local}") String from) {
        this(mailSenderProvider.getIfAvailable(), mailHost, from);
    }

    MailVerificationCodeSender(JavaMailSender mailSender, String mailHost, String from) {
        this.mailSender = mailSender;
        this.mailHost = mailHost == null ? "" : mailHost.trim();
        this.from = from;
    }

    @Override
    public void send(String email, String institutionId, String code) {
        if (!mailHost.isEmpty() && mailSender != null) {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(from);
            message.setTo(email);
            message.setSubject("TrustLayer Kurum Başvurusu Doğrulama Kodu");
            message.setText("Merhaba,\n\n"
                    + institutionId + " kurum başvurunuz için 6 haneli doğrulama kodunuz: " + code
                    + "\nBu kod 15 dakika geçerlidir.\n\nTrustLayer");
            mailSender.send(message);
            log.info("Doğrulama kodu SMTP üzerinden {} adresine gönderildi (başvuru {}).", email, institutionId);
        } else {
            log.info("[DEMO e-posta] {} adresine doğrulama kodu: {} (başvuru {})", email, code, institutionId);
        }
    }
}
