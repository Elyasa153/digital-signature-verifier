package com.trustlayer.dsv.web;

import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Giriş hesapları (FR-8, K11): bir CA yöneticisi + kurum başına bir operatör.
 * Operatör parolaları {@code <runtime>/ra/hesaplar.properties} içinde, yalnız özet olarak.
 * Hiçbir parola koda gömülü değildir ve keystore parolasıyla paylaşılmaz.
 */
@Component
class AccountStore implements UserDetailsService {

    static final String ADMIN = "ca-yonetici";
    static final String ROLE_ADMIN = "CA_ADMIN";
    static final String ROLE_INSTITUTION = "INSTITUTION";

    private static final Logger log = LoggerFactory.getLogger(AccountStore.class);

    private final PasswordEncoder encoder;
    private final Path file;
    private final String adminHash;
    private final SecureRandom random = new SecureRandom();

    AccountStore(PasswordEncoder encoder, @Value("${dsv.runtime-dir}") Path runtimeDir,
            @Value("${dsv.admin-password:}") String adminPassword) {
        this.encoder = encoder;
        this.file = runtimeDir.resolve("ra").resolve("hesaplar.properties");
        if (adminPassword.isEmpty()) {
            adminPassword = newPassword();
            log.warn("DSV_ADMIN_PASSWORD ayarlanmamış; bu çalıştırma için CA yöneticisi ({}) parolası: {}", ADMIN,
                    adminPassword);
        }
        this.adminHash = encoder.encode(adminPassword);
    }

    @Override
    public synchronized UserDetails loadUserByUsername(String username) {
        if (ADMIN.equals(username)) {
            return User.withUsername(ADMIN).password(adminHash).roles(ROLE_ADMIN).build();
        }
        String hash = read().getProperty(username);
        if (hash == null) {
            throw new UsernameNotFoundException(username);
        }
        return User.withUsername(username).password(hash).roles(ROLE_INSTITUTION).build();
    }

    synchronized boolean exists(String username) {
        return ADMIN.equals(username) || read().containsKey(username);
    }

    /** Yeni kurum operatörü; düz parola yalnız bir kez döner, CA yöneticisi kuruma bant dışı iletir. */
    synchronized String createOperator(String institutionId) {
        if (exists(institutionId)) {
            throw new IllegalArgumentException("Hesap zaten var: " + institutionId);
        }
        String password = newPassword();
        setPassword(institutionId, password);
        return password;
    }

    /** Örnek kurumlar için: parolayı (yeniden) ayarlar. */
    synchronized void setPassword(String institutionId, String password) {
        if (ADMIN.equals(institutionId)) {
            throw new IllegalArgumentException("Ayrılmış kullanıcı adı: " + ADMIN);
        }
        Properties p = read();
        p.setProperty(institutionId, encoder.encode(password));
        try {
            Files.createDirectories(file.getParent());
            try (Writer out = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                p.store(out, null);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    String newPassword() {
        byte[] bytes = new byte[12];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private Properties read() {
        Properties p = new Properties();
        if (Files.exists(file)) {
            try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                p.load(in);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return p;
    }
}
