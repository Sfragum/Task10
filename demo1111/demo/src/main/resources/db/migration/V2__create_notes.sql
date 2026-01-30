CREATE TABLE notes (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       title VARCHAR(100) NOT NULL,
                       content TEXT,
                       user_id INTEGER NOT NULL,
                       FOREIGN KEY (user_id) REFERENCES users(id)
);