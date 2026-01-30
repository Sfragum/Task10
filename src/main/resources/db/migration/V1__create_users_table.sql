CREATE TABLE users (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       username VARCHAR(255) NOT NULL UNIQUE,
                       email VARCHAR(255) NOT NULL UNIQUE,
                       password VARCHAR(255) NOT NULL,
                       role VARCHAR(50) DEFAULT 'USER'
);