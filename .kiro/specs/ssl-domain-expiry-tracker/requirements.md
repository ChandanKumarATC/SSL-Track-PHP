# Requirements Document

## Introduction

The SSL & Domain Expiry Tracking Application is a web-based monitoring system that tracks SSL certificate and domain expiration dates, providing automated email notifications to prevent service disruptions. The application will be deployed on AWS EC2 with Apache web server using PHP technology stack.

## Glossary

- **System**: The SSL & Domain Expiry Tracking Application
- **Domain_Monitor**: Component responsible for checking domain expiration dates via WHOIS
- **SSL_Monitor**: Component responsible for checking SSL certificate expiration dates
- **SSL_Generator**: Component responsible for generating and managing Let's Encrypt certificates
- **Notification_Service**: Component responsible for sending email alerts via Gmail SMTP
- **Dashboard**: Web interface displaying tracked items and their status with secure login
- **Tracking_Item**: A domain or SSL certificate being monitored
- **Administrator**: User who manages the tracking system through authenticated web interface
- **WHOIS_Service**: External service providing domain registration information
- **Certificate_Parser**: Component that validates and extracts SSL certificate information
- **Certbot_Manager**: Component that handles Let's Encrypt certificate generation and renewal
- **MySQL_Database**: Database system for storing tracking data and configuration

## Requirements

### Requirement 1: Domain and Certificate Management

**User Story:** As an administrator, I want to manage domains and SSL certificates for tracking, so that I can monitor all critical assets from a central location.

#### Acceptance Criteria

1. WHEN an administrator adds a valid domain name, THE System SHALL store it with domain name, registrar (optional), and admin email(s) in the MySQL database
2. WHEN an administrator adds a domain, THE System SHALL automatically fetch expiration date via WHOIS lookup
3. WHEN an administrator adds a valid SSL certificate endpoint, THE System SHALL detect and store issuer, expiry date, and wildcard status
4. WHEN an administrator removes a tracking item, THE System SHALL delete it from the database and stop monitoring
5. WHEN invalid domain names or SSL endpoints are provided, THE System SHALL reject the input and display appropriate error messages

### Requirement 2: SSL Certificate Monitoring

**User Story:** As an administrator, I want automated SSL certificate expiration monitoring, so that I can prevent certificate-related service outages.

#### Acceptance Criteria

1. WHEN the SSL_Monitor checks a certificate, THE System SHALL retrieve the certificate from the specified endpoint
2. WHEN a valid SSL certificate is retrieved, THE Certificate_Parser SHALL extract the expiration date and validation status
3. WHEN an SSL certificate cannot be retrieved, THE System SHALL log the error and mark the certificate as unreachable
4. WHEN an SSL certificate is expired or invalid, THE System SHALL mark it with error status
5. THE SSL_Monitor SHALL check all tracked certificates at least once every 24 hours

### Requirement 3: Domain Expiration Monitoring

**User Story:** As an administrator, I want automated domain expiration monitoring, so that I can renew domains before they expire and cause service disruptions.

#### Acceptance Criteria

1. WHEN the Domain_Monitor checks a domain, THE System SHALL query the WHOIS_Service for registration information
2. WHEN valid WHOIS data is retrieved, THE System SHALL extract and store the domain expiration date
3. WHEN WHOIS data cannot be retrieved, THE System SHALL log the error and mark the domain as unreachable
4. WHEN WHOIS data indicates an expired domain, THE System SHALL mark it with error status
5. THE Domain_Monitor SHALL check all tracked domains at least once every 24 hours

### Requirement 4: Email Notification System

**User Story:** As an administrator, I want to receive email notifications for upcoming expirations, so that I can take action before services are affected.

#### Acceptance Criteria

1. WHEN an SSL certificate expires within 7 days, THE Notification_Service SHALL send an email alert via Gmail SMTP
2. WHEN a domain expires within 30 days, THE Notification_Service SHALL send an email alert via Gmail SMTP
3. WHEN sending email notifications, THE System SHALL use sender email atc.domain.track@gmail.com with TLS and app password authentication
4. WHEN sending notifications, THE System SHALL include domain name, expiry date, days remaining, and clear subject line with ⚠️ Expiry Alert
5. THE Notification_Service SHALL not send duplicate notifications for the same expiration event within 24 hours

### Requirement 5: Dashboard and Status Display

**User Story:** As an administrator, I want a secure web dashboard to view all tracked items and their status, so that I can quickly assess the health of monitored assets.

#### Acceptance Criteria

1. WHEN an administrator accesses the dashboard, THE System SHALL require session-based authentication before displaying data
2. WHEN displaying the dashboard, THE System SHALL show total domains, domains expiring soon, and SSLs expiring soon
3. WHEN items are safe (not expiring soon), THE Dashboard SHALL display them with green status indicators
4. WHEN items are expiring soon, THE Dashboard SHALL display them with yellow warning indicators
5. WHEN items are expired, THE Dashboard SHALL display them with red error indicators

### Requirement 6: Let's Encrypt SSL Certificate Management

**User Story:** As an administrator, I want to generate and manage Let's Encrypt SSL certificates, so that I can maintain secure connections with automated certificate management.

#### Acceptance Criteria

1. WHEN an administrator requests SSL generation, THE Certbot_Manager SHALL generate Let's Encrypt certificates using DNS-based validation
2. WHEN generating certificates, THE System SHALL support both single domain and wildcard SSL certificates
3. WHEN certificates are generated, THE System SHALL store certificate paths securely in the database
4. WHEN certificates need renewal, THE System SHALL automatically renew them via cron job before expiration
5. WHEN certificate operations complete, THE System SHALL allow administrators to download SSL certificate files

### Requirement 7: Automated Monitoring Schedule

**User Story:** As a system administrator, I want automated scheduled monitoring via cron jobs, so that expiration checks happen without manual intervention.

#### Acceptance Criteria

1. THE System SHALL execute SSL expiry checks daily using Linux cron jobs
2. THE System SHALL execute domain expiry checks daily using Linux cron jobs  
3. WHEN monitoring runs, THE System SHALL generate logs for email sent, failures, and expiry scan results
4. WHEN monitoring encounters errors, THE System SHALL log them and continue processing remaining items
5. THE System SHALL complete monitoring cycles efficiently for tracked items

### Requirement 8: Error Handling and Logging

**User Story:** As an administrator, I want comprehensive error handling and logging, so that I can troubleshoot issues and ensure system reliability.

#### Acceptance Criteria

1. WHEN any system error occurs, THE System SHALL log it with timestamp, error type, and relevant context
2. WHEN network timeouts occur during monitoring, THE System SHALL retry up to 3 times before marking as failed
3. WHEN database operations fail, THE System SHALL log the error and gracefully handle the failure
4. WHEN email sending fails, THE System SHALL log the failure and attempt retry according to configured policy
5. THE System SHALL maintain log files with automatic rotation to prevent disk space issues

### Requirement 9: Security and Access Control

**User Story:** As a security-conscious administrator, I want secure application configuration, so that the monitoring system is protected from unauthorized access.

#### Acceptance Criteria

1. WHEN users access the web interface, THE System SHALL require session-based authentication before displaying any data
2. WHEN storing sensitive configuration data, THE System SHALL not hardcode secrets and use secure configuration management
3. WHEN processing user input, THE System SHALL validate and sanitize all data to prevent injection attacks
4. WHEN accessing external services, THE System SHALL use secure connections (HTTPS/TLS) where available
5. THE System SHALL implement proper session management with automatic timeout for inactive users

### Requirement 10: AWS EC2 and Technology Stack

**User Story:** As a system administrator, I want proper AWS EC2 deployment with specified technology stack, so that the application runs reliably in the cloud environment.

#### Acceptance Criteria

1. WHEN deployed on EC2, THE System SHALL be configured to work with PHP 8.x, Apache web server, and Amazon Linux 2023
2. WHEN using database services, THE System SHALL integrate with MySQL/MariaDB for data storage
3. WHEN handling SSL certificates, THE System SHALL be fully compatible with AWS EC2 and Apache configuration
4. WHEN managing files and logs, THE System SHALL respect EC2 file system permissions and organize files in proper directory structure
5. THE System SHALL include deployment scripts, Apache VirtualHost configuration, and setup instructions for Amazon Linux 2023