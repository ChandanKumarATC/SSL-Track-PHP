# SSL & Domain Expiry Tracker

A PHP-based web application that monitors SSL certificate and domain expiration dates, providing automated email notifications to prevent service disruptions.

## Features

- **SSL Certificate Monitoring**: Automatically checks SSL certificate expiration dates
- **Domain Expiration Tracking**: Monitors domain expiration via WHOIS lookups
- **Email Notifications**: Sends alerts via Gmail SMTP for upcoming expirations
- **Let's Encrypt Integration**: Generate and manage SSL certificates automatically
- **Web Dashboard**: Secure web interface for managing tracked items
- **Automated Monitoring**: Daily cron jobs for hands-off monitoring
- **AWS EC2 Ready**: Optimized for deployment on Amazon Linux 2023

## Requirements

- PHP 8.0 or higher
- MySQL/MariaDB 5.7 or higher
- Apache web server
- OpenSSL extension
- PDO MySQL extension
- cURL extension
- Composer for dependency management

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ssl-domain-expiry-tracker
   ```

2. **Install dependencies**
   ```bash
   composer install
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database and email settings
   ```

4. **Set up database**
   ```bash
   # Create database manually or run:
   mysql -u root -p -e "CREATE DATABASE ssl_domain_tracker"
   
   # Run setup script
   php database/setup.php
   ```

5. **Configure web server**
   - Point document root to the `public` directory
   - Ensure Apache has mod_rewrite enabled
   - Set appropriate file permissions

6. **Set up cron jobs**
   ```bash
   # Add to crontab (crontab -e)
   0 6 * * * /usr/bin/php /path/to/ssl-domain-tracker/cron/monitor_ssl.php
   0 7 * * * /usr/bin/php /path/to/ssl-domain-tracker/cron/monitor_domains.php
   ```

## Directory Structure

```
ssl-domain-expiry-tracker/
├── public/              # Web root directory
│   └── index.php       # Main entry point
├── config/             # Configuration files
│   └── config.php      # Main configuration
├── database/           # Database schema and setup
│   ├── schema.sql      # Database schema
│   ├── setup.php       # Setup script
│   └── Database.php    # Database connection class
├── src/                # Application source code
│   ├── Models/         # Data models
│   ├── Services/       # Business logic services
│   ├── Controllers/    # Web controllers
│   └── Utils/          # Utility classes
├── cron/               # Cron job scripts
│   ├── monitor_ssl.php # SSL monitoring cron
│   └── monitor_domains.php # Domain monitoring cron
├── logs/               # Application logs
├── ssl/                # SSL certificate storage
├── tests/              # Unit and integration tests
└── vendor/             # Composer dependencies
```

## Configuration

### Database Settings
Configure database connection in `.env`:
```
DB_HOST=localhost
DB_NAME=ssl_domain_tracker
DB_USER=your_db_user
DB_PASS=your_db_password
```

### Email Settings
Configure Gmail SMTP in `.env`:
```
SMTP_USERNAME=atc.domain.track@gmail.com
SMTP_PASSWORD=your_app_password
```

### Notification Thresholds
- SSL certificates: 7 days warning
- Domains: 30 days warning

## Usage

1. **Access the web dashboard** at your configured domain
2. **Add domains and SSL certificates** to monitor
3. **Configure email recipients** for notifications
4. **Let the cron jobs handle monitoring** automatically

## Development

### Running Tests
```bash
composer test
```

### Code Quality
```bash
composer phpstan    # Static analysis
composer phpcs      # Code style check
composer phpcbf     # Code style fix
```

### Database Management
```bash
composer install-db  # Install database schema
```

## Deployment on AWS EC2

This application is optimized for deployment on Amazon Linux 2023 with Apache and PHP 8.x. Detailed deployment instructions will be provided in the deployment configuration task.

## Security

- Session-based authentication
- CSRF protection
- Input validation and sanitization
- Secure configuration management
- TLS/HTTPS for external connections

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions, please check the documentation or create an issue in the repository.