package com.example.demo.security;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimiter {

    private static final int MAX_REQUESTS = 5;        // izin verilen max istek sayısı
    private static final long WINDOW_MS = 60_000;     // zaman penceresi 1 dakika

    private static class RequestInfo {
        int count;
        long windowStart;

        RequestInfo() {
            this.count = 1;
            this.windowStart = Instant.now().toEpochMilli();
        }
    }

    private final Map<String, RequestInfo> requests = new ConcurrentHashMap<>();

    public boolean isAllowed(String key) {
        long now = Instant.now().toEpochMilli();
        requests.putIfAbsent(key, new RequestInfo());

        RequestInfo info = requests.get(key);

        if (now - info.windowStart > WINDOW_MS) {
            // zaman penceresi doldu, sayacı sıfırla
            info.count = 1;
            info.windowStart = now;
            return true;
        } else {
            if (info.count < MAX_REQUESTS) {
                info.count++;
                return true;
            } else {
                return false; // limit aşıldı
            }
        }
    }
}
