-- Create roles table
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(200)
);

-- Create users table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create user_roles junction table
CREATE TABLE user_roles (
    user_id UUID NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Create otps table
CREATE TABLE otps (
    id UUID PRIMARY KEY,
    email VARCHAR(100) NOT NULL,
    code VARCHAR(10) NOT NULL,
    expiry_time TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    type VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default roles
INSERT INTO roles (name, description) VALUES 
    ('ROLE_USER', 'Regular user with basic privileges'),
    ('ROLE_ADMIN', 'Administrator with full privileges'),
    ('ROLE_MODERATOR', 'Moderator with intermediate privileges');

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_otps_email_code_type ON otps(email, code, type);