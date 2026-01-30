package com.example.demo.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

class PasswordEncoderTest {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    @Test
    void encode_should_hash_password_and_matches_should_work() {
        String plainPassword = "Password12345";

        String hashed = encoder.encode(plainPassword);

        assertNotNull(hashed);
        assertNotEquals(plainPassword, hashed); // should not be plain text
        assertTrue(hashed.startsWith("$2a$12$")); // BCrypt prefix + strength 12

        // matches should return true for the same password
        assertTrue(encoder.matches(plainPassword, hashed));

        // matches should return false for a wrong password
        assertFalse(encoder.matches("wrongPassword", hashed));
    }

    @Test
    void different_encode_calls_should_generate_different_hashes() {
        String password = "SamePassword";

        String hash1 = encoder.encode(password);
        String hash2 = encoder.encode(password);

        assertNotEquals(hash1, hash2); // BCrypt generates different hashes due to salt
        assertTrue(encoder.matches(password, hash1));
        assertTrue(encoder.matches(password, hash2));
    }
}
