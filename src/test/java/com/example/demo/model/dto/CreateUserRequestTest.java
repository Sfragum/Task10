package com.example.demo.model.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CreateUserRequestTest {

    private static Validator validator;

    @BeforeAll
    static void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void should_not_have_errors_with_valid_input() {
        CreateUserRequest request = new CreateUserRequest();
        request.setUsername("john123");
        request.setEmail("john@example.com");
        request.setPassword("Password123");

        Set<ConstraintViolation<CreateUserRequest>> violations = validator.validate(request);

        assertTrue(violations.isEmpty(), "There should be no errors for valid input");
    }

    @Test
    void should_return_error_if_username_is_too_short() {
        CreateUserRequest request = new CreateUserRequest();
        request.setUsername("jo"); // min 3
        request.setEmail("test@example.com");
        request.setPassword("Password123");

        Set<ConstraintViolation<CreateUserRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertEquals(1, violations.size());
        assertTrue(violations.iterator().next().getMessage().contains("size must be between 3 and 50"));
    }

    @Test
    void should_return_error_if_username_is_not_alphanumeric() {
        CreateUserRequest request = new CreateUserRequest();
        request.setUsername("john@123"); // @ is invalid
        request.setEmail("test@example.com");
        request.setPassword("Password123");

        Set<ConstraintViolation<CreateUserRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertTrue(violations.iterator().next().getMessage().contains("Username must be alphanumeric"));
    }

    @Test
    void should_return_error_if_password_is_too_short() {
        CreateUserRequest request = new CreateUserRequest();
        request.setUsername("john123");
        request.setEmail("test@example.com");
        request.setPassword("short");

        Set<ConstraintViolation<CreateUserRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertTrue(violations.iterator().next().getMessage().contains("size must be between 8 and"));
    }

    @Test
    void should_return_error_if_email_format_is_invalid() {
        CreateUserRequest request = new CreateUserRequest();
        request.setUsername("john123");
        request.setEmail("invalid-email");
        request.setPassword("Password123");

        Set<ConstraintViolation<CreateUserRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertTrue(violations.iterator().next().getMessage().contains("must be a well-formed email address"));
    }
}
