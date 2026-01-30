package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.model.dto.AuthResponse;
import com.example.demo.model.dto.CreateUserRequest;
import com.example.demo.model.dto.LoginRequest;
import com.example.demo.model.dto.RefreshRequest;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(AuthenticationManager authenticationManager,
                          UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody CreateUserRequest request, HttpServletResponse response) {
        if (userRepository.findByUsername(request.getUsername()) != null) {
            logger.warn("Registration attempt with taken username: {}", request.getUsername());
            return ResponseEntity.badRequest().body(new AuthResponse(null, "Username is already taken"));
        }
        if (request.getPassword().length() < 8 || List.of("password", "123456").contains(request.getPassword())) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, "Password does not meet policy"));
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        addCookie(response, "accessToken", accessToken, 15 * 60, true);
        addCookie(response, "refreshToken", refreshToken, 7 * 24 * 60 * 60, true);
        logger.info("User registered: {}", user.getUsername());
        return ResponseEntity.ok(new AuthResponse(accessToken, "Registration successful"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            User user = (User) authentication.getPrincipal();
            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            addCookie(response, "accessToken", accessToken, 15 * 60, true);
            addCookie(response, "refreshToken", refreshToken, 7 * 24 * 60 * 60, true);
            logger.info("User logged in: {}", user.getUsername());
            return ResponseEntity.ok(new AuthResponse(accessToken, "Login successful"));
        } catch (BadCredentialsException e) {
            logger.warn("Failed login attempt for username: {}", request.getUsername());
            return ResponseEntity.badRequest().body(new AuthResponse(null, "Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request, HttpServletResponse response) {
        String oldRefreshToken = request.getRefreshToken();
        if (jwtService.isRefreshTokenValid(oldRefreshToken)) {
            String username = jwtService.extractUsername(oldRefreshToken);
            User user = userRepository.findByUsername(username);
            if (user != null) {
                String newAccessToken = jwtService.generateToken(user);
                String newRefreshToken = jwtService.generateRefreshToken(user);
                jwtService.blacklistToken(oldRefreshToken); // Rotation
                addCookie(response, "accessToken", newAccessToken, 15 * 60, true);
                addCookie(response, "refreshToken", newRefreshToken, 7 * 24 * 60 * 60, true);
                logger.info("Token refreshed for user: {}", username);
                return ResponseEntity.ok(new AuthResponse(newAccessToken, "Token refreshed"));
            }
        }
        logger.warn("Invalid refresh token attempt");
        return ResponseEntity.badRequest().body(new AuthResponse(null, "Invalid refresh token"));
    }

    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader("Authorization");
        String jwt = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
        } else if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    jwt = cookie.getValue();
                    break;
                }
            }
        }

        if (jwt != null) {
            jwtService.blacklistToken(jwt);
        }

        // Expire cookies
        addCookie(response, "accessToken", null, 0, true);
        addCookie(response, "refreshToken", null, 0, true);
        logger.info("User logged out");
        return ResponseEntity.ok(new AuthResponse(null, "Logout successful"));
    }

    private void addCookie(HttpServletResponse response, String name, String value, int maxAge, boolean secure) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Strict"); // Fallback for older Spring
        response.addCookie(cookie);
    }
}