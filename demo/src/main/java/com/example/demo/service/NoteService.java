package com.example.demo.service;

import com.example.demo.model.Note;
import com.example.demo.model.User;
import com.example.demo.repository.NoteRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;

@Service
public class NoteService {

    private final NoteRepository noteRepository;

    public NoteService(NoteRepository noteRepository) {
        this.noteRepository = noteRepository;
    }

    public List<Note> getNotesForUser(User user) {
        return noteRepository.findAllByUser(user);
    }

    public Note getNote(Long id, User user) {
        Note note = noteRepository.findById(id).orElseThrow(NoSuchElementException::new);
        if (!note.getUser().getId().equals(user.getId())) {
            throw new AccessDeniedException("You do not own this note");
        }
        return note;
    }

    public Note createNote(Note note) {
        return noteRepository.save(note);
    }

    public Note updateNote(Note note) {
        return noteRepository.save(note);
    }

    public void deleteNote(Long id, User user) {
        Note note = getNote(id, user);
        noteRepository.delete(note);
    }
}
