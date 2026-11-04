package com.trustlayer.dsv.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * FR-8 ve FR-9 güvenlik yapılandırması:
 * - /dogrula ve /crl herkese açıktır, hesap gerektirmez (FR-9).
 * - /panel giriş gerektirir; girişsiz istekler /login sayfasına yönlendirilir (FR-8).
 */
@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.ignoringRequestMatchers("/dogrula", "/panel", "/logout"))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/dogrula", "/crl", "/style.css", "/login", "/error").permitAll()
                .requestMatchers("/panel", "/panel/**").authenticated()
                .anyRequest().permitAll()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/panel", true)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?cikis")
                .permitAll()
            );
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(
            PasswordEncoder encoder,
            @Value("${dsv.keystore-password:}") String keystorePassword) {
        String rawPassword = keystorePassword.isEmpty() ? "kurum123" : keystorePassword;
        String encoded = encoder.encode(rawPassword);

        return new InMemoryUserDetailsManager(
            User.withUsername("ornek-universite").password(encoded).roles("INSTITUTION").build(),
            User.withUsername("ornek-hastane").password(encoded).roles("INSTITUTION").build()
        );
    }
}
