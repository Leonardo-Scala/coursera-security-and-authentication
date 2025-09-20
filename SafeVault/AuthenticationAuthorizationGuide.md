# SafeVault Authentication & Authorization Implementation

## ??? Overview

SafeVault now implements a comprehensive authentication and authorization system with the following key security features:

- **JWT-based Authentication**: Secure token-based authentication with access and refresh tokens
- **Role-based Authorization**: Three-tier role system (User, Admin, SuperAdmin)
- **Password Security**: BCrypt hashing with strong password policies
- **Audit Logging**: Comprehensive security event tracking
- **Input Sanitization**: Protection against SQL injection and XSS attacks
- **Session Management**: Secure session tracking and token invalidation

## ?? Authentication System

### User Roles

1. **User** (Default role)
   - Access own profile and data
   - Submit user data
   - Change own password

2. **Admin**
   - All User permissions
   - View all users
   - Update user roles (except SuperAdmin)
   - View audit logs and security events
   - Deactivate user accounts

3. **SuperAdmin**
   - All Admin permissions
   - Promote users to any role (including SuperAdmin)
   - View system statistics
   - Delete user accounts
   - Full administrative access

### Default Accounts

The system comes with pre-configured accounts for testing:

```
SuperAdmin Account:
- Username: admin
- Email: admin@safevault.com
- Password: Admin123!

Regular User Account:
- Username: testuser
- Email: user@safevault.com
- Password: User123!
```

## ?? API Endpoints

### Authentication Endpoints (`/api/auth`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/login` | User authentication | No |
| POST | `/register` | User registration | No |
| POST | `/refresh` | Refresh JWT tokens | No |
| POST | `/logout` | User logout | Yes |
| POST | `/change-password` | Change user password | Yes |
| GET | `/profile` | Get current user profile | Yes |
| GET | `/validate` | Validate current token | Yes |

### Admin Endpoints (`/api/admin`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/users` | Get all users | Admin+ |
| PUT | `/users/{id}/role` | Update user role | Admin+ |
| PUT | `/users/{id}/deactivate` | Deactivate user | Admin+ |
| GET | `/audit-logs` | Get audit logs | Admin+ |
| GET | `/security-events` | Get security events | Admin+ |
| GET | `/statistics` | Get system statistics | SuperAdmin |

### User Data Endpoints (`/api/users`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/submit` | Submit user data | User+ |
| GET | `/{username}` | Get user by username | User+ (own data) / Admin+ (any data) |
| GET | `/` | Get all users | Admin+ |
| DELETE | `/{id}` | Delete user | SuperAdmin |

## ?? Configuration

### JWT Settings (appsettings.json)

```json
{
  "JwtSettings": {
    "SecretKey": "Your-Super-Secret-Key-Here",
    "Issuer": "SafeVault",
    "Audience": "SafeVault-Users",
    "ExpiryMinutes": "60"
  }
}
```

### Security Policies

- **Access Token**: Expires in 1 hour
- **Refresh Token**: Expires in 7 days
- **Password Requirements**: 
  - Minimum 8 characters
  - At least 1 uppercase letter
  - At least 1 lowercase letter
  - At least 1 digit
  - At least 1 special character

## ?? Testing the System

### Running Authentication Tests

```bash
cd "8 - Security and Authentication\Modulo 4\SafeVault"
dotnet test --filter "AuthenticationAuthorizationTests"
```

### API Testing with Postman/curl

1. **Register a new user**:
```bash
curl -X POST "https://localhost:5001/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "NewUser123!",
    "confirmPassword": "NewUser123!"
  }'
```

2. **Login and get token**:
```bash
curl -X POST "https://localhost:5001/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "User123!"
  }'
```

3. **Access protected endpoint**:
```bash
curl -X GET "https://localhost:5001/api/auth/profile" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

4. **Access admin endpoint**:
```bash
curl -X GET "https://localhost:5001/api/admin/users" \
  -H "Authorization: Bearer YOUR_ADMIN_JWT_TOKEN_HERE"
```

## ?? Security Features

### Input Sanitization
- All user inputs are sanitized using `InputSanitizer`
- Protection against SQL injection attacks
- XSS prevention through HTML tag stripping
- Unicode normalization to prevent character-based attacks

### Password Security
- BCrypt hashing with work factor 12
- Strong password policy enforcement
- Password change invalidates all existing sessions

### Session Management
- JWT tokens with configurable expiration
- Refresh token rotation
- Session tracking in database
- Logout invalidates all user sessions

### Audit Logging
- All authentication events logged
- User actions tracked with timestamps
- IP address and user agent recording
- Success/failure status for security monitoring

## ?? Database Schema

### Users Table
```sql
CREATE TABLE Users (
    UserID INT IDENTITY(1,1) PRIMARY KEY,
    Username NVARCHAR(100) UNIQUE NOT NULL,
    Email NVARCHAR(255) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(MAX) NOT NULL,
    Role NVARCHAR(50) DEFAULT 'User',
    CreatedAt DATETIME2 DEFAULT GETUTCDATE(),
    LastLoginAt DATETIME2,
    IsActive BIT DEFAULT 1,
    RefreshToken NVARCHAR(MAX),
    RefreshTokenExpiryTime DATETIME2
);
```

### UserSessions Table
```sql
CREATE TABLE UserSessions (
    SessionID INT IDENTITY(1,1) PRIMARY KEY,
    UserID INT FOREIGN KEY REFERENCES Users(UserID),
    SessionToken NVARCHAR(500) UNIQUE NOT NULL,
    CreatedAt DATETIME2 DEFAULT GETUTCDATE(),
    ExpiresAt DATETIME2 NOT NULL,
    IPAddress NVARCHAR(45),
    UserAgent NVARCHAR(500),
    IsActive BIT DEFAULT 1
);
```

### AuditLogs Table
```sql
CREATE TABLE AuditLogs (
    AuditID INT IDENTITY(1,1) PRIMARY KEY,
    UserID INT FOREIGN KEY REFERENCES Users(UserID),
    Action NVARCHAR(100) NOT NULL,
    Resource NVARCHAR(200) NOT NULL,
    Timestamp DATETIME2 DEFAULT GETUTCDATE(),
    IPAddress NVARCHAR(45),
    Details NVARCHAR(1000),
    Success BIT NOT NULL
);
```

## ?? Security Events Monitored

- LOGIN_SUCCESS / LOGIN_FAILED
- REGISTRATION_SUCCESS / REGISTRATION_FAILED
- PASSWORD_CHANGE_SUCCESS / PASSWORD_CHANGE_FAILED
- TOKEN_REFRESH_SUCCESS / REFRESH_TOKEN_FAILED
- LOGOUT_SUCCESS
- ROLE_UPDATE
- USER_DEACTIVATED
- ACCESS_DENIED
- AUTHORIZATION_SUCCESS

## ?? Best Practices Implemented

1. **Principle of Least Privilege**: Users can only access resources appropriate to their role
2. **Defense in Depth**: Multiple layers of security (input sanitization, parameterized queries, authorization)
3. **Secure by Default**: New users get minimal permissions
4. **Audit Trail**: All security-relevant actions are logged
5. **Token Expiration**: Short-lived access tokens with refresh capability
6. **Password Security**: Strong hashing and policy enforcement
7. **Input Validation**: All inputs validated and sanitized
8. **Error Handling**: Generic error messages to prevent information disclosure

## ?? Monitoring and Alerts

Admins can monitor security through:
- `/api/admin/security-events` - Recent authentication events
- `/api/admin/audit-logs` - Full audit trail
- `/api/admin/statistics` - System-wide security statistics

Key metrics to monitor:
- Failed login attempts
- Unusual access patterns
- Role changes
- Account deactivations
- Token refresh failures

## ??? Production Deployment Considerations

1. **Change JWT Secret**: Use a strong, unique secret key in production
2. **Use HTTPS**: Always use TLS in production
3. **Database Security**: Use proper database credentials and connection encryption
4. **Rate Limiting**: Implement rate limiting for authentication endpoints
5. **Monitoring**: Set up log aggregation and alerting
6. **Backup**: Regular backup of user data and audit logs
7. **Updates**: Keep all dependencies updated for security patches