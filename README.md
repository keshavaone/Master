# GUARD: Secure PII Data Management System

## Project Overview

GUARD is a comprehensive, secure system for managing Personally Identifiable Information (PII) with enterprise-grade security features. The application encrypts sensitive data using AWS Key Management Service (KMS), stores it securely, and provides a user-friendly interface for authorized access and management.

flowchart TB
    subgraph "Frontend Container"
        UI[UI Application]
        SessionManager[Session Manager]
        UI --> SessionManager
    end
    
    subgraph "API Container"
        API[API Service]
        Auth[Auth Service]
        KMS[KMS Integration]
        DB[DynamoDB Access]
        Audit[Audit Logger]
        
        API --> Auth
        API --> KMS
        API --> DB
        API --> Audit
        Auth --> KMS
    end
    
    subgraph "AWS Services"
        DynamoDB[(DynamoDB Primary)]
        DynamoDBReplica[(DynamoDB Replica)]
        KMSService[KMS]
        S3[S3 Bucket]
        SecretsManager[Secrets Manager]
        IAM[IAM/SSO]
        
        DynamoDB --> DynamoDBReplica
        DB --> DynamoDB
        KMS --> KMSService
        Audit --> S3
        Auth --> IAM
        Auth --> SecretsManager
    end
    
    UI -->|Secure API Calls| API
    SessionManager -->|AWS SSO Token| Auth
    SessionManager -->|JWT Token| UI
    
    style API fill:#f9f,stroke:#333,stroke-width:2px
    style UI fill:#bbf,stroke:#333,stroke-width:2px
    style DynamoDB fill:#bfb,stroke:#333,stroke-width:2px
    style DynamoDBReplica fill:#bfb,stroke:#333,stroke-width:2px,stroke-dasharray: 5 5
    style KMSService fill:#fbb,stroke:#333,stroke-width:2px
    style IAM fill:#fbf,stroke:#333,stroke-width:2px

## Key Features

- **End-to-End Encryption**: All sensitive data is encrypted using AWS KMS with AES-256
- **Secure Authentication**: Multi-factor authentication for access to PII data
- **Role-Based Access Control**: Granular permissions for data access
- **Audit Logging**: Comprehensive logging of all access and modifications
- **Secure Storage**: Data stored in encrypted format in AWS DynamoDB
- **User-Friendly Interface**: Desktop application with intuitive controls
- **Data Categorization**: Organize PII data by categories and types
- **Backup and Recovery**: Automated backup to AWS S3 with versioning

## Project Structure

```
/
├── API/                           # Backend API and core functionality
│   ├── assistant.py               # Helper functions for logging and utilities
│   ├── backend.py                 # Core business logic for data processing
│   ├── CONSTANTS.py               # Configuration constants
│   ├── KMS.py                     # Encryption/decryption using AWS KMS
│   ├── main.py                    # FastAPI endpoints for PII management
│   └── store_secrets.py           # AWS Secrets Manager integration
├── UI/
│   └── Desktop/
│       └── main.py                # PyQt5 desktop application interface
└── .github/
    └── workflows/
        └── pylint.yml             # CI pipeline for code quality
```

## Technical Details

### Backend (API)

The backend is built with FastAPI and provides a set of RESTful endpoints for PII data management. It handles:

- Authentication and authorization
- Data encryption/decryption
- CRUD operations for PII data
- Secure storage in AWS DynamoDB
- Audit logging to S3

### Security Layer

- **KMS Integration**: Uses AWS KMS for key management
- **Fernet Encryption**: Implements symmetric encryption with rotation capabilities
- **Secure Key Storage**: Keys never stored in plaintext
- **Token-Based Authentication**: Secure authentication flow

### Desktop UI

The desktop application provides a secure interface for:

- User authentication
- Browsing categorized PII data
- Adding new PII entries
- Editing and deleting existing entries
- Viewing audit logs
- Downloading encrypted backups

## Setup and Installation

### Prerequisites

- Python 3.8+
- AWS Account with configured:
  - KMS
  - DynamoDB
  - S3
  - Secrets Manager
- PyQt5

### Environment Setup

1. Clone the repository:
   ```
   https://github.com/keshavaone/Master.git
   cd Master
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up AWS credentials:
   ```
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_REGION=your_region
   export AWS_KEY=your_kms_key_id
   export APP_PASSWORD=your_app_password
   ```

4. Create a CONSTANTS.py file in the API directory with:
   ```python
   AWS_S3 = "your-s3-bucket-name"
   AWS_FILE = "your-data-file.xlsx"
   DATA_FILE_CSV = "data_export.csv"
   URL = "http://localhost:8000/pii"
   APP_PASSWORD = os.environ.get("APP_PASSWORD", "default_password")
   ```

### Running the Application

1. Start the API server:
   ```
   cd API
   python main.py
   ```

2. Launch the desktop client:
   ```
   cd UI/Desktop
   python main.py
   ```

3. Use the provided initial credentials to log in:
   - Username: [Contact administrator]
   - Password: [Secret environment variable]

## Security Considerations

- All PII data is encrypted before storage
- Passwords are never stored in plaintext
- All access is logged for audit purposes
- Regular key rotation is implemented
- Application logs are encrypted and stored securely

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

The system is designed with a security-first approach, using AWS services for key management, encryption, and secure storage. The desktop application provides a controlled environment for accessing this sensitive data, with comprehensive logging to track all access and modifications.

The architecture follows a client-server model with end-to-end encryption, ensuring that data is protected both at rest and in transit. Authentication is handled securely with multiple verification steps, and all actions are logged for audit purposes.

## License

This project is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

## Contact

For more information, please contact the project maintainers.
