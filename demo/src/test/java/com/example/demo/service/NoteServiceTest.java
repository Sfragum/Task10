package com.example.demo.service;

import com.example.demo.model.Note;
import com.example.demo.model.User;
import com.example.demo.repository.NoteRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NoteServiceTest {

    @Mock
    private NoteRepository noteRepository;

    @InjectMocks
    private NoteService noteService;

    private User user1;
    private User user2;
    private Note noteOfUser1;

    @BeforeEach
    void setUp() {
        user1 = new User();
        user1.setId(1L);
        user1.setUsername("user1");

        user2 = new User();
        user2.setId(2L);
        user2.setUsername("user2");

        noteOfUser1 = new Note();
        noteOfUser1.setId(100L);
        noteOfUser1.setTitle("Personal note");
        noteOfUser1.setContent("Only user1 can see this");
        noteOfUser1.setUser(user1);
    }

    @Test
    void getNotesForUser_should_return_only_users_own_notes() {
        when(noteRepository.findAllByUser(user1)).thenReturn(List.of(noteOfUser1));

        List<Note> notes = noteService.getNotesForUser(user1);

        assertEquals(1, notes.size());
        assertEquals("Personal note", notes.get(0).getTitle());
        verify(noteRepository).findAllByUser(user1);
    }

    @Test
    void getNote_user_requesting_own_note_should_succeed() {
        when(noteRepository.findById(100L)).thenReturn(Optional.of(noteOfUser1));

        Note found = noteService.getNote(100L, user1);

        assertEquals("Personal note", found.getTitle());
    }

    @Test
    void getNote_user_requesting_someone_elses_note_should_throw_AccessDeniedException() {
        when(noteRepository.findById(100L)).thenReturn(Optional.of(noteOfUser1));

        assertThrows(AccessDeniedException.class, () -> {
            noteService.getNote(100L, user2);
        });
    }

    @Test
    void createNote_should_save_and_return_note() {
        Note newNote = new Note();
        newNote.setTitle("New note");

        when(noteRepository.save(any(Note.class))).thenAnswer(invocation -> {
            Note arg = invocation.getArgument(0);
            arg.setId(999L); // simulate returning id after save
            return arg;
        });

        Note saved = noteService.createNote(newNote);

        assertNotNull(saved);
        assertEquals("New note", saved.getTitle());
        verify(noteRepository).save(newNote);
    }

    @Test
    void deleteNote_user_deleting_own_note_should_succeed() {
        when(noteRepository.findById(100L)).thenReturn(Optional.of(noteOfUser1));

        noteService.deleteNote(100L, user1);

        verify(noteRepository).delete(noteOfUser1);
    }

    @Test
    void deleteNote_user_trying_to_delete_someone_elses_note_should_throw_error() {
        when(noteRepository.findById(100L)).thenReturn(Optional.of(noteOfUser1));

        assertThrows(AccessDeniedException.class, () -> {
            noteService.deleteNote(100L, user2);
        });
        verify(noteRepository, never()).delete(any());
    }
}
