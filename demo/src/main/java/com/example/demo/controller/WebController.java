package com.example.demo.controller;

import com.example.demo.model.Note;
import com.example.demo.model.User;
import com.example.demo.model.dto.CreateUserRequest;
import com.example.demo.model.dto.NoteRequest;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.NoteService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
public class WebController {

    private final NoteService noteService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public WebController(NoteService noteService,
                         UserRepository userRepository,
                         PasswordEncoder passwordEncoder) {
        this.noteService = noteService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/notes";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String registerForm(Model model) {
        model.addAttribute("createUserRequest", new CreateUserRequest());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("createUserRequest") CreateUserRequest request,
                           BindingResult result,
                           Model model,
                           RedirectAttributes redirectAttributes) {

        System.out.println("REGISTRATION ATTEMPT STARTED");
        System.out.println("Username from form: '" + request.getUsername() + "'");
        System.out.println("Email from form: '" + request.getEmail() + "'");
        System.out.println("Password from form (plain text): '" + request.getPassword() + "'");

        if (result.hasErrors()) {
            System.out.println("Validation errors found: " + result.getAllErrors());
            return "register";
        }

        String username = request.getUsername().trim();
        String email = request.getEmail().trim();

        System.out.println("Trimmed username: '" + username + "'");
        System.out.println("Trimmed email: '" + email + "'");

        if (userRepository.findByUsername(username) != null) {
            System.out.println("Username already exists: " + username);
            model.addAttribute("error", "This username is already taken!");
            return "register";
        }

        if (request.getPassword().length() < 8) {
            System.out.println("Password is too short");
            model.addAttribute("error", "Password must be at least 8 characters long!");
            return "register";
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        String hashedPassword = passwordEncoder.encode(request.getPassword());
        user.setPassword(hashedPassword);
        userRepository.save(user);

        System.out.println("REGISTRATION SUCCESSFUL! Hashed password: " + hashedPassword);
        redirectAttributes.addFlashAttribute("message", "Registration successful! You can now log in.");
        return "redirect:/login";
    }

    @GetMapping("/notes")
    public String notes(Model model, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            System.out.println("Access to notes page denied: User not authenticated!");
            return "redirect:/login";
        }

        User user = (User) authentication.getPrincipal();
        System.out.println("User accessing notes page: " + user.getUsername());

        List<Note> notes = noteService.getNotesForUser(user);
        model.addAttribute("notes", notes);
        model.addAttribute("noteRequest", new NoteRequest());
        model.addAttribute("username", user.getUsername());

        return "notes";
    }

    @PostMapping("/notes")
    public String createNote(@Valid @ModelAttribute NoteRequest noteRequest,
                             BindingResult result,
                             Model model,
                             Authentication authentication,
                             RedirectAttributes redirectAttributes) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }

        System.out.println("Attempting to add new note: " + noteRequest.getTitle());

        if (result.hasErrors()) {
            System.out.println("Note validation errors: " + result.getAllErrors());
            User user = (User) authentication.getPrincipal();
            model.addAttribute("notes", noteService.getNotesForUser(user));
            model.addAttribute("error", "Title field is required!");
            return "notes";
        }

        User user = (User) authentication.getPrincipal();
        Note note = new Note();
        note.setTitle(noteRequest.getTitle());
        note.setContent(noteRequest.getContent());
        note.setUser(user);
        noteService.createNote(note);

        redirectAttributes.addFlashAttribute("message", "Note added successfully!");
        return "redirect:/notes";
    }

    @PostMapping("/notes/{id}/delete")
    public String deleteNote(@PathVariable Long id,
                             Authentication authentication,
                             RedirectAttributes redirectAttributes) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }

        User user = (User) authentication.getPrincipal();
        System.out.println("Attempting to delete note: ID " + id + " - User: " + user.getUsername());

        try {
            noteService.deleteNote(id, user);
            redirectAttributes.addFlashAttribute("message", "Note deleted.");
        } catch (Exception e) {
            System.out.println("Delete error: " + e.getMessage());
            redirectAttributes.addFlashAttribute("error", "This note does not belong to you or was not found!");
        }

        return "redirect:/notes";
    }
}
