-- Initialize vulnerable database

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(200),
    ssn VARCHAR(20),
    credit_card VARCHAR(20),
    role VARCHAR(20) DEFAULT 'user',
    reset_token VARCHAR(100),
    security_question VARCHAR(200),
    api_key VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    author VARCHAR(100),
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200),
    price DECIMAL(10,2),
    data JSONB
);

CREATE TABLE IF NOT EXISTS secrets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    value TEXT
);

-- Insert sample data
INSERT INTO users (username, password, email, ssn, credit_card, role, security_question, api_key) VALUES
('admin', 'admin123', 'admin@vulnapp.local', '123-45-6789', '4111-1111-1111-1111', 'admin', 'What is your pet name?', 'sk-admin-secret-key-12345'),
('john', 'password123', 'john@example.com', '234-56-7890', '4222-2222-2222-2222', 'user', 'What is your mothers maiden name?', 'sk-user-key-67890'),
('jane', 'jane2024', 'jane@example.com', '345-67-8901', '4333-3333-3333-3333', 'user', 'What city were you born in?', 'sk-user-key-11111'),
('guest', 'guest', 'guest@example.com', '456-78-9012', '4444-4444-4444-4444', 'guest', 'What is your favorite color?', 'sk-guest-key-22222'),
('root', 'toor', 'root@localhost', '567-89-0123', '4555-5555-5555-5555', 'admin', 'What is 2+2?', 'sk-root-key-33333');

INSERT INTO comments (author, content) VALUES
('Admin', 'Welcome to our vulnerable app!'),
('Hacker', '<script>alert("XSS")</script>'),
('User', 'This is a normal comment'),
('Tester', '<img src=x onerror=alert("Stored XSS")>'),
('Developer', '<svg onload=alert("SVG XSS")>');

INSERT INTO products (name, price, data) VALUES
('Laptop', 999.99, '{"category": "electronics", "stock": 50}'),
('Phone', 599.99, '{"category": "electronics", "stock": 100}'),
('Tablet', 399.99, '{"category": "electronics", "stock": 75}');

INSERT INTO secrets (name, value) VALUES
('DATABASE_PASSWORD', 'super_secret_db_pass'),
('API_KEY', 'sk-live-abcdef123456'),
('JWT_SECRET', 'my_jwt_secret_key'),
('AWS_SECRET', 'aws_secret_access_key_123'),
('ENCRYPTION_KEY', 'aes256_encryption_key_xyz');

-- Create views for easier exploitation
CREATE OR REPLACE VIEW user_credentials AS
SELECT id, username, password, email, role FROM users;
