package com.example.demo.repository;

import com.example.demo.model.Note;
import com.example.demo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface NoteRepository extends JpaRepository<Note, Long> {

    List<Note> findAllByUser(User user);

    @Query(value = "SELECT * FROM notes WHERE id = ?1 AND user_id = ?2", nativeQuery = true)
    Note findByIdAndUserId(Long id, Long userId);
}
