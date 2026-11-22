package com.trustlayer.dsv.web;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * /basvuru için IP başına kayan pencere hız sınırı: 10 dakikada en fazla 5 başvuru.
 */
@Component
class BasvuruRateLimiter {

    static final int MAX_REQUESTS = 5;
    static final Duration WINDOW = Duration.ofMinutes(10);

    private final ConcurrentHashMap<String, Deque<Instant>> hits = new ConcurrentHashMap<>();
    private final Clock clock;

    @Autowired
    BasvuruRateLimiter() {
        this(Clock.systemUTC());
    }

    BasvuruRateLimiter(Clock clock) {
        this.clock = clock;
    }

    /** Sınır aşılmadıysa isteği kaydeder ve true döner; aşıldıysa false. */
    boolean tryAcquire(String ip) {
        String key = (ip == null || ip.isBlank()) ? "unknown" : ip;
        Instant now = clock.instant();
        Instant cutoff = now.minus(WINDOW);

        Deque<Instant> timestamps = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (timestamps) {
            while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(cutoff)) {
                timestamps.pollFirst();
            }
            if (timestamps.size() >= MAX_REQUESTS) {
                return false;
            }
            timestamps.addLast(now);
            return true;
        }
    }

    /** Testlerin birbirini etkilememesi için sayacı sıfırlar. */
    void reset() {
        hits.clear();
    }
}
