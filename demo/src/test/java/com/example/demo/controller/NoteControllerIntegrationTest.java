package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.security.JwtAuthFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@Import(JwtAuthFilter.class)
class NoteControllerIntegrationTest {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext context;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    /**
     * Test that an unauthenticated user is redirected to the login page when accessing a protected endpoint.
     * Expected: 302 Found (redirect to /login)
     */
    @Test
    void unauthenticatedUserShouldBeRedirectedToLogin() throws Exception {
        mockMvc.perform(get("/api/notes"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    /**
     * Test that an authenticated user can access the protected /api/notes endpoint.
     * Expected: 200 OK
     */
    @Test
    void authenticatedUserCanAccessApiNotes() throws Exception {
        User testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("Furkan");

        Authentication auth = new UsernamePasswordAuthenticationToken(
                testUser,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        mockMvc.perform(get("/api/notes"))
                .andExpect(status().isOk());
    }

    /**
     * Test access control: authenticated user should NOT access another user's note.
     * Expected: 404 Not Found (if note does not exist) or 403 Forbidden (if ownership check fails)
     * Note: Use a real note ID from your database that belongs to another user or does not exist.
     */
    @Test
    void authenticatedUserCannotAccessAnotherUsersNote() throws Exception {
        User testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("Furkan");

        Authentication auth = new UsernamePasswordAuthenticationToken(
                testUser,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Use a real note ID that belongs to another user (check your DB)
        mockMvc.perform(get("/api/notes/4"))  // ← Change 4 to a real foreign note ID
                .andExpect(status().isNotFound());  // or .isForbidden() if ownership check is strict
    }

    /**
     * Test that form POST without CSRF token is rejected (CSRF protection active).
     * Expected: 403 Forbidden
     */
    @Test
    void formPostWithoutCsrfTokenShouldBeRejected() throws Exception {
        // Simulate authenticated user
        User testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("Furkan");

        Authentication auth = new UsernamePasswordAuthenticationToken(
                testUser,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        mockMvc.perform(post("/notes")  // ← Change to your real form POST endpoint if different
                        .param("title", "Test Title")
                        .param("content", "Test Content")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isForbidden());  // CSRF token missing → 403
    }

    /**
     * Test that form POST with valid CSRF token succeeds.
     * Expected: 3xx Redirection (e.g., to /notes after successful save)
     */
    @Test
    void formPostWithCsrfTokenShouldSucceed() throws Exception {
        // Simulate authenticated user
        User testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("Furkan");

        Authentication auth = new UsernamePasswordAuthenticationToken(
                testUser,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        mockMvc.perform(post("/notes")  // ← Change to your real form POST endpoint if different
                        .param("title", "Test Title")
                        .param("content", "Test Content")
                        .with(csrf())  // Add valid CSRF token
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().is3xxRedirection())  // Successful → redirect
                .andExpect(redirectedUrl("/notes"));  // Adjust to your actual success URL
    }
}