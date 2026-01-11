CREATE TABLE IF NOT EXISTS notes (
                                     id BIGINT PRIMARY KEY,
                                     title TEXT NOT NULL,
                                     content TEXT,
                                     user_id BIGINT NOT NULL,
                                     FOREIGN KEY (user_id) REFERENCES users(id)
    );