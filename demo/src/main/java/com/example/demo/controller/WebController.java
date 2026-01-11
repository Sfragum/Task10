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

        System.out.println("KAYIT DENEMESİ BAŞLADI");
        System.out.println("Formdan gelen username: '" + request.getUsername() + "'");
        System.out.println("Formdan gelen email: '" + request.getEmail() + "'");
        System.out.println("Formdan gelen password (düz metin): '" + request.getPassword() + "'");

        if (result.hasErrors()) {
            return "register";
        }

        String username = request.getUsername().trim();
        String email = request.getEmail().trim();

        if (userRepository.findByUsername(username) != null) {
            model.addAttribute("error", "Bu kullanıcı adı zaten alınmış!");
            return "register";
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        redirectAttributes.addFlashAttribute("message", "Kayıt başarılı! Giriş yapabilirsiniz.");
        return "redirect:/login";
    }

    @GetMapping("/notes")
    public String notes(Model model, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }

        User user = (User) authentication.getPrincipal();
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

        if (result.hasErrors()) {
            User user = (User) authentication.getPrincipal();
            model.addAttribute("notes", noteService.getNotesForUser(user));
            model.addAttribute("error", "Başlık alanı zorunlu!");
            return "notes";
        }

        User user = (User) authentication.getPrincipal();
        Note note = new Note();
        note.setTitle(noteRequest.getTitle());
        note.setContent(noteRequest.getContent());
        note.setUser(user);
        noteService.createNote(note);

        redirectAttributes.addFlashAttribute("message", "Not başarıyla eklendi!");
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

        try {
            noteService.deleteNote(id, user);
            redirectAttributes.addFlashAttribute("message", "Not silindi.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Bu not size ait değil veya bulunamadı!");
        }

        return "redirect:/notes";
    }
}
