-- Örnek kullanıcılar ekle (password'leri düz metin olarak koyuyorum, ama gerçekte BCrypt ile hash'le!)
-- Eğer Spring Security kullanıyorsan, {noop} prefix ekle veya hash'le.

INSERT INTO users (username, email, password)
VALUES ('admin', 'admin@example.com', '{noop}admin123');

INSERT INTO users (username, email, password)
VALUES ('test', 'test@example.com', '{noop}test123');