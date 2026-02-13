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

-- Insert sample data with realistic information for CTF
INSERT INTO users (username, password, email, ssn, credit_card, role, security_question, api_key) VALUES
('admin', 'admin123', 'admin@luxora.com', '123-45-6789', '4111-1111-1111-1111', 'admin', 'What is your pet name?', 'sk-admin-secret-key-12345'),
('john', 'password123', 'john@example.com', '234-56-7890', '4222-2222-2222-2222', 'user', 'What is your mothers maiden name?', 'sk-user-key-67890'),
('jane', 'jane2024', 'jane@example.com', '345-67-8901', '4333-3333-3333-3333', 'user', 'What city were you born in?', 'sk-user-key-11111'),
('guest', 'guest', 'guest@example.com', '456-78-9012', '4444-4444-4444-4444', 'guest', 'What is your favorite color?', 'sk-guest-key-22222'),
('root', 'toor', 'root@localhost', '567-89-0123', '4555-5555-5555-5555', 'admin', 'What is 2+2?', 'sk-root-key-33333'),
-- Additional admin accounts for privilege escalation
('superadmin', 'Sup3rS3cr3t!', 'superadmin@luxora-internal.com', '678-90-1234', '4666-6666-6666-6666', 'superadmin', 'Company founded year?', 'sk-superadmin-FLAG{pr1v1l3g3_3sc4l4t10n_m4st3r}'),
('dbadmin', 'D8bas3P@ss!', 'dbadmin@luxora-internal.com', '789-01-2345', '4777-7777-7777-7777', 'admin', 'Database port?', 'sk-dbadmin-key-55555'),
('backup_admin', 'backup2024', 'backup@luxora.com', '890-12-3456', '4888-8888-8888-8888', 'admin', 'Backup server name?', 'sk-backup-key-66666'),
-- CTF targets with sensitive data
('ctf_flag_holder', 'Fl4gH0ld3r#', 'flags@luxora-ctf.internal', '901-23-4567', '4999-9999-9999-9999', 'user', 'CTF challenge?', 'FLAG{sql_1nj3ct10n_m4st3r}'),
('developer', 'D3vT3st!ng', 'dev@luxora.com', '012-34-5678', '4000-0000-0000-0000', 'developer', 'IDE name?', 'sk-dev-key-77777');

INSERT INTO comments (author, content) VALUES
('Admin', 'Welcome to our vulnerable app!'),
('Hacker', '<script>alert("XSS")</script>'),
('User', 'This is a normal comment'),
('Tester', '<img src=x onerror=alert("Stored XSS")>'),
('Developer', '<svg onload=alert("SVG XSS")>');

INSERT INTO products (name, price, image_url, data) VALUES
('Classic Leather Tote', 299.99, 'https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=800', '{"category": "Bags", "stock": 50, "badge": "Sale", "original_price": 399.99, "description": "Handcrafted Italian leather tote with gold hardware"}'),
('Minimalist Watch', 189.00, 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=800', '{"category": "Accessories", "stock": 100, "badge": "New", "description": "Swiss movement, sapphire crystal, water resistant"}'),
('Cashmere Sweater', 249.00, 'https://images.unsplash.com/photo-1434389677669-e08b4cac3105?w=800', '{"category": "Clothing", "stock": 75, "description": "100% Mongolian cashmere, ethically sourced"}'),
('Silk Scarf Collection', 89.00, 'https://images.unsplash.com/photo-1601924994987-69e26d50dc26?w=800', '{"category": "Accessories", "stock": 200, "badge": null, "original_price": 129.00, "description": "Hand-rolled edges, 100% mulberry silk"}'),
('Premium Sunglasses', 159.00, 'https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=800', '{"category": "Accessories", "stock": 60, "badge": "Best Seller", "description": "UV400 protection, titanium frame"}'),
('Leather Belt', 79.00, 'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=800', '{"category": "Accessories", "stock": 150, "description": "Full grain leather, solid brass buckle"}'),
('Wool Blend Coat', 449.00, 'https://images.unsplash.com/photo-1539533018447-63fcce2678e3?w=800', '{"category": "Clothing", "stock": 30, "badge": "New", "description": "Italian wool blend, satin lined"}'),
('Merino Wool Cardigan', 189.00, 'https://images.unsplash.com/photo-1594938298603-c8148c4dae35?w=800', '{"category": "Clothing", "stock": 45, "description": "New Zealand merino, button front"}'),
('Italian Leather Wallet', 129.00, 'https://images.unsplash.com/photo-1627123424574-724758594e93?w=800', '{"category": "Accessories", "stock": 80, "description": "RFID blocking, vegetable tanned leather"}'),
('Cotton Oxford Shirt', 89.00, 'https://images.unsplash.com/photo-1596755094514-f87e34085b2c?w=800', '{"category": "Clothing", "stock": 120, "description": "Egyptian cotton, mother of pearl buttons"}'),
('Linen Summer Dress', 179.00, 'https://images.unsplash.com/photo-1595777457583-95e059d581b8?w=800', '{"category": "Clothing", "stock": 55, "badge": "Sale", "original_price": 229.00, "description": "French linen, relaxed fit"}'),
('Handcrafted Bracelet', 69.00, 'https://images.unsplash.com/photo-1611652022419-a9419f74343d?w=800', '{"category": "Accessories", "stock": 90, "description": "Sterling silver, artisan made"}'),
('Travel Duffel Bag', 349.00, 'https://images.unsplash.com/photo-1553062407-98eeb64c6a45?w=800', '{"category": "Bags", "stock": 25, "badge": "Limited", "description": "Canvas and leather, brass hardware"}'),
('Cashmere Beanie', 79.00, 'https://images.unsplash.com/photo-1576871337632-b9aef4c17ab9?w=800', '{"category": "Accessories", "stock": 100, "description": "100% cashmere, ribbed knit"}'),
('Silk Pocket Square Set', 49.00, 'https://images.unsplash.com/photo-1598560917505-59a3ad559071?w=800', '{"category": "Accessories", "stock": 150, "badge": "Best Seller", "description": "Set of 3, hand-rolled edges"}');

INSERT INTO secrets (name, value) VALUES
('DATABASE_PASSWORD', 'super_secret_db_pass'),
('API_KEY', 'sk-live-abcdef123456'),
('JWT_SECRET', 'my_jwt_secret_key'),
('AWS_SECRET', 'aws_secret_access_key_123'),
('ENCRYPTION_KEY', 'aes256_encryption_key_xyz');

-- Create views for easier exploitation
CREATE OR REPLACE VIEW user_credentials AS
SELECT id, username, password, email, role FROM users;
