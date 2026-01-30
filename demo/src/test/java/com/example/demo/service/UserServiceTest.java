package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    // This means "we are using a fake (mock) UserRepository instead of the real one"
    @Mock
    private UserRepository userRepository;

    // We are testing UserService and injecting the fake repository into it
    @InjectMocks
    private UserService userService;

    @Test
    void should_return_user_details_if_user_exists() {
        // 1. Prepare a fake user for the test
        User fakeUser = new User();
        fakeUser.setUsername("john123");
        fakeUser.setPassword("password123");

        // 2. When "findByUsername" is called, return the fake user
        when(userRepository.findByUsername("john123")).thenReturn(fakeUser);

        // 3. Actual test: call the method
        var foundUser = userService.loadUserByUsername("john123");

        // 4. Verify expectations
        assertNotNull(foundUser);
        assertEquals("john123", foundUser.getUsername());
    }

    @Test
    void should_throw_error_if_user_does_not_exist() {
        // 1. Indicate that this user does not exist
        when(userRepository.findByUsername("non_existing_user")).thenReturn(null);

        // 2. Expect this call to throw an exception
        assertThrows(UsernameNotFoundException.class, () -> {
            userService.loadUserByUsername("non_existing_user");
        });
    }
}
