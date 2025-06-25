-- backtoschool_app/database.sql
USE back2school;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    role ENUM('parent', 'school', 'retailer', 'admin') NOT NULL,
    admission_number VARCHAR(50) NULL,
    school_id INT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (school_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE school_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    school_id INT NOT NULL,
    item_name VARCHAR(50) NOT NULL,
    allowed BOOLEAN DEFAULT TRUE,
    max_quantity INT NULL,
    FOREIGN KEY (school_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    retailer_id INT NOT NULL,
    item_name VARCHAR(50) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    stock INT NOT NULL,
    FOREIGN KEY (retailer_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE carts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE cart_items (
    cart_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    is_compliant BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (cart_id, product_id),
    FOREIGN KEY (cart_id) REFERENCES carts(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

CREATE TABLE wallets (
    user_id INT PRIMARY KEY,
    balance DECIMAL(10,2) DEFAULT 0.00,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    cart_id INT NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    status ENUM('pending', 'shipped', 'delivered') DEFAULT 'pending',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (cart_id) REFERENCES carts(id) ON DELETE CASCADE
);

CREATE TABLE notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE registration_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    role ENUM('school', 'retailer') NOT NULL,
    used BOOLEAN DEFAULT FALSE
);

-- Initial admin and school
INSERT INTO users (username, password, role) VALUES 
('admin', 'admin123', 'admin'),
('school1', 'school123', 'school');

-- Add is_approved field for retailers
ALTER TABLE users 
ADD COLUMN is_approved BOOLEAN DEFAULT FALSE;

-- Insert sample registration codes (in production, generate these securely)
INSERT INTO registration_codes (code, role) VALUES
('SCHOOL-CODE-123', 'school'),
('RETAILER-CODE-456', 'retailer');