package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.model.dto.AuthResponse;
import com.example.demo.model.dto.CreateUserRequest;
import com.example.demo.model.dto.LoginRequest;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.JwtService;
import com.example.demo.security.RateLimiter;
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
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RateLimiter rateLimiter;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    public AuthController(AuthenticationManager authenticationManager,
                          UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtService jwtService,
                          RateLimiter rateLimiter) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody CreateUserRequest request,
                                                 @RequestHeader(value = "X-Forwarded-For", required = false) String ip) {

        String clientIp = ip != null ? ip : "unknown";

        if (!rateLimiter.isAllowed(clientIp)) {
            logger.warn("Rate limit exceeded for registration from IP: [{}]", clientIp);
            return ResponseEntity.status(429)
                    .body(new AuthResponse(null, "Too many requests. Try again later."));
        }

        if (userRepository.findByUsername(request.getUsername()) != null) {
            logger.warn("Registration failed: Username already taken [{}]", request.getUsername());
            return ResponseEntity.badRequest()
                    .body(new AuthResponse(null, "Username is already taken"));
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        String jwt = jwtService.generateToken(user);
        logger.info("User registered successfully: [{}]", user.getUsername());
        return ResponseEntity.ok(new AuthResponse(jwt, "Registration successful"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request,
                                              @RequestHeader(value = "X-Forwarded-For", required = false) String ip) {

        String clientIp = ip != null ? ip : "unknown";

        if (!rateLimiter.isAllowed(clientIp)) {
            logger.warn("Rate limit exceeded for login from IP: [{}]", clientIp);
            return ResponseEntity.status(429)
                    .body(new AuthResponse(null, "Too many requests. Try again later."));
        }

        try {
            Authentication authentication =
                    authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    request.getUsername(),
                                    request.getPassword()
                            )
                    );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtService.generateToken((User) authentication.getPrincipal());

            logger.info("User logged in successfully: [{}]", request.getUsername());
            return ResponseEntity.ok(new AuthResponse(jwt, "Login successful"));
        } catch (BadCredentialsException ex) {
            logger.warn("Failed login attempt for username: [{}] from IP: [{}]", request.getUsername(), clientIp);
            return ResponseEntity.status(401)
                    .body(new AuthResponse(null, "Invalid username or password"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestParam String refreshToken,
                                                     @RequestHeader(value = "X-Forwarded-For", required = false) String ip) {

        String clientIp = ip != null ? ip : "unknown";

        if (!rateLimiter.isAllowed(clientIp)) {
            logger.warn("Rate limit exceeded for refresh from IP: [{}]", clientIp);
            return ResponseEntity.status(429)
                    .body(new AuthResponse(null, "Too many requests. Try again later."));
        }

        if (!jwtService.isRefreshTokenValid(refreshToken)) {
            logger.warn("Invalid or expired refresh token used from IP: [{}]", clientIp);
            return ResponseEntity.status(401)
                    .body(new AuthResponse(null, "Invalid or expired refresh token"));
        }

        String username = jwtService.extractUsername(refreshToken);
        User user = userRepository.findByUsername(username);

        String newRefreshToken = jwtService.rotateRefreshToken(refreshToken, user);
        String newAccessToken = jwtService.generateToken(user);

        logger.info("Refresh token rotated for user: [{}] from IP: [{}]", username, clientIp);
        return ResponseEntity.ok(new AuthResponse(newAccessToken, "Refresh successful"));
    }

    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(@RequestParam String refreshToken) {
        if (refreshToken != null && !refreshToken.isEmpty()) {
            jwtService.blacklistToken(refreshToken);
        }

        SecurityContextHolder.clearContext();
        logger.info("User logged out successfully");
        return ResponseEntity.ok(new AuthResponse(null, "Logged out successfully"));
    }
}
