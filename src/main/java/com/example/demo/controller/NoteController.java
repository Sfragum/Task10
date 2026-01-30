package com.example.demo.controller;

import com.example.demo.model.Note;
import com.example.demo.model.User;
import com.example.demo.model.dto.NoteRequest;
import com.example.demo.service.NoteService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notes")
@PreAuthorize("isAuthenticated()")
public class NoteController {

    private final NoteService noteService;

    public NoteController(NoteService noteService) {
        this.noteService = noteService;
    }

    @GetMapping
    public List<Note> getNotes() {
        User user = (User) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        return noteService.getNotesForUser(user);
    }

    @GetMapping("/{id}")
    public Note getNote(@PathVariable Long id) {
        User user = (User) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        return noteService.getNote(id, user);
    }

    @PostMapping
    public ResponseEntity<Note> createNote(@Valid @RequestBody NoteRequest request) {
        User user = (User) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        Note note = new Note();
        note.setTitle(request.getTitle());
        note.setContent(request.getContent());
        note.setUser(user);
        return ResponseEntity.status(201).body(noteService.createNote(note));
    }

    @PutMapping("/{id}")
    public Note updateNote(@PathVariable Long id,
                           @Valid @RequestBody NoteRequest request) {
        User user = (User) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        Note note = noteService.getNote(id, user);
        note.setTitle(request.getTitle());
        note.setContent(request.getContent());
        return noteService.updateNote(note);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteNote(@PathVariable Long id) {
        User user = (User) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        noteService.deleteNote(id, user);
        return ResponseEntity.noContent().build();
    }
}
