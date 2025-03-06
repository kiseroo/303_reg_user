# User Authentication System

A secure user authentication system with encrypted data storage built with Node.js, Express, and SQLite.

## Features

- User registration with encrypted personal data
- Secure login system
- Auto-generated registration numbers
- Passport registration number support
- Data encryption using AES-256-CBC
- Password hashing with bcrypt

## Technologies Used

- Node.js
- Express.js
- SQLite3 database
- Crypto for encryption
- Bcrypt for password hashing

## Installation

1. Clone the repository
   ```
   git clone https://github.com/your-username/user-authentication-system.git
   cd user-authentication-system
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Start the server
   ```
   node app.js
   ```

4. Access the application at `http://localhost:3000`

## Usage

### Registration

Fill in the registration form with your:
- Email address
- Password
- Father's name
- First name
- Address
- Phone number
- Passport registration number (optional)

### Login

Use your email address and password to log in.

## Security Features

- All personal data is encrypted using AES-256-CBC
- Passwords are hashed using bcrypt
- Auto-generated unique registration numbers
- Secure data handling throughout the application

## Project Structure

- `app.js` - Main application file
- `public/` - Static files (HTML, CSS)
- `database.sqlite` - SQLite database file

## License

This project is licensed under the MIT License