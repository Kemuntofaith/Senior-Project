USE back2school;

-- 2. Users table (Parents, Schools, Retailers)
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    role ENUM('parent', 'school', 'retailer') NOT NULL,
    school_id INT NULL  -- Links parents to their school
);