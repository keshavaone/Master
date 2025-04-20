# GUARD: Secure PII Data Management System

## Project Overview

GUARD is a comprehensive, secure system for managing Personally Identifiable Information (PII) with enterprise-grade security features. The application encrypts sensitive data using AWS Key Management Service (KMS), stores it securely, and provides a user-friendly interface for authorized access and management.

## Key Features

- **End-to-End Encryption**: All sensitive data is encrypted using AWS KMS with AES-256
- **Secure Authentication**: Multi-factor authentication for access to PII data
- **Role-Based Access Control**: Granular permissions for data access
- **Audit Logging**: Comprehensive logging of all access and modifications
- **Secure Storage**: Data stored in encrypted format in AWS DynamoDB
- **User-Friendly Interface**: Both desktop and web applications with intuitive controls
- **Data Categorization**: Organize PII data by categories and types
- **Backup and Recovery**: Automated backup to AWS S3 with versioning
- **Calendar Integration**: Scheduling and notification capabilities
- **Advanced Security**: Rate limiting, token blacklisting, and security headers
- **Performance Optimizations**: Response caching, GZip compression, and connection pooling

## Recent Improvements

The codebase has been significantly improved with the following updates:

1. **Enhanced Security**:
   - Implemented rate limiting to prevent brute force attacks
   - Added token blacklisting for secure logout
   - Applied comprehensive security headers to all responses
   - Improved input validation and sanitization
   - **Added AWS SSO Authentication** with browser-based login flow

2. **Performance Optimization**:
   - Added response caching for faster data retrieval
   - Implemented GZip compression for reduced payload size
   - Optimized database connection pooling
   - Reduced unnecessary debug logging

3. **Improved Architecture**:
   - Better separation of concerns
   - Enhanced error handling
   - Added performance monitoring
   - More robust API metrics

4. **Development Experience**:
   - Enhanced logging with rotation and better formatting
   - Improved startup configuration
   - Support for multiple worker processes
   - Added OAuth2 support for better integration

## Project Structure

```
/
├── api/                           # Backend API and core functionality
│   ├── auth/                      # Authentication and authorization
│   ├── controllers/               # API route controllers
│   ├── data/                      # Data access layer
│   ├── encryption/                # KMS encryption/decryption
│   ├── communications/            # Email and messaging services
│   ├── security/                  # Security enhancements
│   └── main.py                    # FastAPI application
├── UI/
│   └── Desktop/                   # PyQt5 desktop application
├── guard-frontend/                # React web application
│   ├── src/                       # Source code
│   └── public/                    # Static assets
├── src/                           # Shared components
└── logs/                          # Application logs
```

## Technical Details

### Backend (API)

The backend is built with FastAPI and provides a set of RESTful endpoints for PII data management:

- Authentication with JWT, OAuth2, and AWS SSO
- Data encryption/decryption with AWS KMS
- CRUD operations for PII data
- Secure storage in AWS DynamoDB
- Comprehensive audit logging
- Performance metrics and monitoring

### Security Layer

- **KMS Integration**: Uses AWS KMS for key management
- **Fernet Encryption**: Implements symmetric encryption with rotation
- **Secure Key Storage**: Keys never stored in plaintext
- **Token-Based Authentication**: Multiple secure authentication flows
- **Rate Limiting**: Prevents abuse and brute force attacks
- **Security Headers**: Protects against common web vulnerabilities

### Frontend Applications

#### Desktop UI (PyQt5)
- User authentication
- PII data management
- Audit log viewing
- Secure backup and restore

#### Web UI (React)
- Modern responsive interface
- Secure JWT authentication
- Dashboard with metrics
- Calendar notifications

## Setup and Installation

### Prerequisites

- Python 3.9+
- AWS Account with configured:
  - KMS
  - DynamoDB
  - S3
  - Secrets Manager
  - SSO (for AWS SSO authentication)
- Node.js 14+ (for web frontend)

### Environment Setup

1. Clone the repository:
   ```
   git clone https://github.com/keshavaone/Master.git
   cd Master
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv myenv
   source myenv/bin/activate  # On Windows: myenv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables by creating a `.env` file:
   ```
   # API Configuration
   API_HOST=0.0.0.0
   API_PORT=8000
   API_VERSION=1.0.0
   ENVIRONMENT=development
   API_WORKERS=1
   LOG_LEVEL=info
   
   # Authentication
   JWT_SECRET=your-secret-key
   JWT_ALGORITHM=HS256
   
   # AWS Configuration
   AWS_REGION=us-east-1
   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   KMS_KEY_ID=your_kms_key_id
   AWS_LOGIN_URL=https://d-9067c603c9.awsapps.com/start/
   AWS_SSO_ENABLED=true
   
   # Development Options
   RELOAD=true
   USE_MOCK_DB=true
   ```

### Running the API

Start the API server:
```bash
python run.py
```

The API will be available at http://localhost:8000 with documentation at http://localhost:8000/docs

### Running the Web Frontend

To run the React frontend:

```bash
cd guard-frontend
npm install
npm start
```

The web application will be available at http://localhost:3000

### Running the Desktop Client

Launch the desktop client:
```
cd UI/Desktop
python main.py
```

## Security Considerations

- All PII data is encrypted before storage
- Passwords are never stored in plaintext
- All access is logged for audit purposes
- Regular key rotation is implemented
- Application logs are encrypted and stored securely
- Rate limiting prevents brute force attacks
- Security headers protect against common web vulnerabilities
- AWS SSO integration provides secure, centralized authentication
- Browser-based login flow with token session management
- Session timeout management with automatic token refresh

## Development and Contributing

We use pylint for code quality assurance. Before submitting a PR:

1. Run pylint:
   ```
   pylint $(git ls-files '*.py')
   ```

2. Ensure all tests pass:
   ```
   pytest tests/
   ```

## Project Context

This project was developed to address the need for secure PII data management in organizations handling sensitive personal information. It combines enterprise-grade security features with a user-friendly interface, making it suitable for various industries including:

- Healthcare (for HIPAA compliance)
- Financial services (for PCI DSS compliance)
- Legal firms handling confidential client information
- HR departments managing employee data
- Government agencies handling citizen information

The system is designed with a security-first approach, using AWS services for key management, encryption, and secure storage.

## License

This project is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

## Contact

For more information, please contact the project maintainers.