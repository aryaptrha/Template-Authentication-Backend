# Authentication API

A comprehensive Spring Boot API for user registration with email OTP verification and role management.

## Overview

This project provides a secure and feature-rich user management system with:

- User registration with email verification
- JWT-based authentication
- Role-based authorization
- Email OTP verification
- Password reset functionality
- User activity tracking

## Technical Specifications

- **Java Version**: 17
- **Spring Boot Version**: 3.2.12
- **Database**: PostgreSQL
- **Dependencies**:
  - Spring Security
  - JWT Authentication
  - Spring Data JPA
  - Spring Mail
  - Flyway Migration*
  - Thymeleaf
  - Lombok

## Prerequisites

- JDK 17+
- Maven 3.6+
- PostgreSQL 14+
- SMTP server for email (e.g., Gmail, SendGrid)

## Getting Started

### Database Setup

1. Create a PostgreSQL database:
```sql
CREATE DATABASE user_registration;
```

2. The tables will be created automatically through Flyway migrations when the application starts.

### Configuration

Edit the `application.properties` file:

```properties
# Server Configuration
server.port=8080
server.servlet.context-path=/api

# Database Configuration
spring.datasource.url=jdbc:postgresql://localhost:5432/user_registration
spring.datasource.username=your-username
spring.datasource.password=your-password

# JWT Configuration
app.jwt.secret=your-jwt-secret-key-should-be-at-least-256-bits
app.jwt.expiration=86400000

# Email Configuration
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=your-email@gmail.com
spring.mail.password=your-app-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true

# OTP Configuration
app.otp.validity-minutes=10
app.otp.length=6
```

### Building and Running

```bash
# Build the project
mvn clean package

# Run the application
java -jar target/user-registration-api-0.0.1-SNAPSHOT.jar
```

Or using Maven:

```bash
mvn spring-boot:run
```

## Usage Guide

### User Registration Flow

1. **Register a new user**
2. **Verify email with OTP**
3. **Login to receive JWT token**
4. **Use the token for authenticated requests**

### API Endpoints

#### Authentication

- **POST /api/auth/register** - Register a new user
- **POST /api/auth/verify-otp** - Verify email with OTP
- **POST /api/auth/login** - Login and get JWT token
- **POST /api/auth/resend-otp** - Resend verification OTP
- **POST /api/auth/forgot-password** - Request password reset
- **POST /api/auth/reset-password** - Reset password with OTP
- **POST /api/auth/register-admin** - Register a new admin (admin only)

#### User Management

- **GET /api/users/me** - Get current user information
- **PUT /api/users/{userId}/roles/{roleName}** - Assign role to user (admin only)

### Example Requests

#### Register a User

```
POST /api/auth/register
```
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "password": "P@ssw0rd123!"
}
```

#### Verify OTP

```
POST /api/auth/verify-otp
```
```json
{
  "email": "john.doe@example.com",
  "otp": "123456"
}
```

#### Login

```
POST /api/auth/login
```
```json
{
  "email": "john.doe@example.com",
  "password": "P@ssw0rd123!"
}
```

#### Request Password Reset

```
POST /api/auth/forgot-password
```
```json
{
  "email": "john.doe@example.com"
}
```

#### Reset Password

```
POST /api/auth/reset-password
```
```json
{
  "email": "john.doe@example.com",
  "otp": "123456",
  "newPassword": "NewP@ssw0rd123!"
}
```

#### Create Admin User (Admin only)

```
POST /api/auth/register-admin
```
Headers:
```
Authorization: Bearer your-jwt-token
```
Body:
```json
{
  "firstName": "Admin",
  "lastName": "User",
  "email": "admin@example.com",
  "password": "Admin@123456"
}
```

## Security Features

- **Password Encryption**: BCrypt password encoder
- **JWT Authentication**: Secure, stateless authentication
- **Role-Based Authorization**: Different access levels (USER, ADMIN, MODERATOR)
- **Email Verification**: OTP verification to validate user emails
- **Password Policies**: Strong password requirements

## Database Schema

The application uses the following main tables:
- `users` - User information
- `roles` - Available roles
- `user_roles` - Junction table for user-role relationships
- `otps` - Stores OTPs for verification

## Extending the API

### Adding New Roles

1. Add the role constant in the `Role` class
2. Insert the role in the database

### Custom Validation

Add custom validation by creating validators and using them with annotations.

## Troubleshooting

### Common Issues

1. **Email not received**: Check spam folder, verify SMTP configuration
2. **JWT expired**: Token lifespan is configured in properties file
3. **Database connection**: Verify PostgreSQL is running and credentials are correct

### Logs

Check the logs for detailed error information:
```
tail -f logs/application.log
```

## License

[MIT License](LICENSE)

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request
