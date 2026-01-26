package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String cleanedUsername = username != null ? username.trim() : null;

        User user = userRepository.findByUsername(cleanedUsername);

        if (user == null) {
            throw new UsernameNotFoundException("Kullanıcı bulunamadı: '" + cleanedUsername + "'");
        }

        System.out.println("Giriş yapan kullanıcı bulundu: " + user.getUsername());
        return user;
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username.trim());
    }
}
