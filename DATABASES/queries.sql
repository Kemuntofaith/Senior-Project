USE back2school;

-- 2. Users table (Parents, Schools, Retailers)
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    role ENUM('parent', 'school', 'retailer') NOT NULL,
    school_id INT NOT NULL  -- Links parents to their school
);

-- 3. School-approved items
CREATE TABLE school_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    school_id INT NOT NULL,
    item_name VARCHAR(50) NOT NULL,
    allowed BOOLEAN DEFAULT TRUE,
    max_quantity INT NULL,
    FOREIGN KEY (school_id) REFERENCES users(id)
);

-- 4. Retailer products
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    retailer_id INT NOT NULL,
    item_name VARCHAR(50) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    stock INT NOT NULL,
    FOREIGN KEY (retailer_id) REFERENCES users(id)
);

-- 5. Shopping carts
CREATE TABLE carts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 6. Cart items (with compliance status)
CREATE TABLE cart_items (
    cart_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    is_compliant BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (cart_id, product_id),
    FOREIGN KEY (cart_id) REFERENCES carts(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- 7. Wallets (Savings + Donations)
CREATE TABLE wallets (
    user_id INT PRIMARY KEY,
    balance DECIMAL(10,2) DEFAULT 0.00,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 8. Orders
CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    cart_id INT NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    status ENUM('pending', 'shipped', 'delivered') DEFAULT 'pending',
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (cart_id) REFERENCES carts(id)
);

-- 9. Notifications
CREATE TABLE notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);