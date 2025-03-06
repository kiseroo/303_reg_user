const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(bodyParser.json());

const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

// Check if users table exists and create it if it doesn't
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    father_name TEXT,
    first_name TEXT,
    address TEXT,
    phone TEXT UNIQUE,
    reg_number TEXT UNIQUE,
    passport_reg_number TEXT
  )`);
});

// Helper function to encrypt data
function encryptData(data, password) {
  const key = crypto.createHash('sha256').update(password).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Helper function to decrypt data
function decryptData(data, password) {
  const key = crypto.createHash('sha256').update(password).digest();
  const parts = data.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = parts.join(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Root endpoint
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register endpoint
app.post('/register', async (req, res) => {
  const { email, password, father_name, first_name, address, phone, passport_reg_number } = req.body;
  
  // Auto-generate registration number
  let reg_number = '';
  
  // Get the highest registration number from the database
  db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
    if (err) return res.status(500).send('Error generating registration number');
    
    // Create a new registration number by incrementing the count
    const count = row ? row.count + 1 : 1;
    reg_number = `#${count}`;
    
    // Validate input
    if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email)) {
      return res.status(400).send('Invalid email format');
    }
    if (!/^[А-Яа-яЁёA-Za-z\s]+$/.test(father_name) || !/^[А-Яа-яЁёA-Za-z\s]+$/.test(first_name) || !/^[А-Яа-яЁёA-Za-z\s]+$/.test(address)) {
      return res.status(400).send('Personal information must be in Cyrillic or Latin');
    }

    // Check for duplicate entries
    db.get('SELECT * FROM users WHERE email = ? OR phone = ? OR (father_name = ? AND first_name = ?)', 
      [email, phone, father_name, first_name], (err, row) => {
      if (row) {
        if (row.email === email) {
          return res.status(400).send('Email already registered');
        }
        return res.status(400).send('Duplicate entry found');
      }

      // Encrypt password and personal data
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Error encrypting password');
        
        try {
          const encryptedEmail = encryptData(email, hashedPassword);
          const encryptedFatherName = encryptData(father_name, hashedPassword);
          const encryptedFirstName = encryptData(first_name, hashedPassword);
          const encryptedAddress = encryptData(address, hashedPassword);
          const encryptedPhone = encryptData(phone, hashedPassword);
          const encryptedRegNumber = encryptData(reg_number, hashedPassword);
          
          // Handle passport_reg_number more carefully
          let encryptedPassportRegNumber = null;
          if (passport_reg_number && passport_reg_number.trim() !== '') {
            encryptedPassportRegNumber = encryptData(passport_reg_number, hashedPassword);
          }
          
          console.log('Attempting to insert user with data:', {
            email,
            hasPasswordLength: hashedPassword ? hashedPassword.length : 0,
            father_name,
            first_name,
            address,
            phone,
            reg_number,
            hasPassportRegNumber: passport_reg_number ? true : false
          });

          // Insert user into database
          db.run(`INSERT INTO users (email, password, father_name, first_name, address, phone, reg_number, passport_reg_number) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, 
            [encryptedEmail, hashedPassword, encryptedFatherName, encryptedFirstName, encryptedAddress, encryptedPhone, encryptedRegNumber, encryptedPassportRegNumber], 
            (err) => {
              if (err) {
                console.error('Database error during user insertion:', err);
                return res.status(500).send('Error saving user: ' + err.message);
              }
              res.status(201).send(`User registered successfully with registration number: ${reg_number}`);
          });
        } catch (error) {
          console.error('Error during data encryption:', error);
          return res.status(500).send('Error processing registration data');
        }
      });
    });
  });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Log the received email and password
  console.log('Login attempt:', { email, password });

  db.all('SELECT * FROM users', (err, rows) => {
    if (err) {
      console.log('Error retrieving users:', err);
      return res.status(500).send('Internal server error');
    }

    let user = null;
    try {
      for (const row of rows) {
        try {
          console.log('Checking user with ID:', row.id);
          const decryptedEmail = decryptData(row.email, row.password);
          console.log('Decrypted email:', decryptedEmail, 'comparing with:', email);
          if (decryptedEmail === email) {
            user = row;
            break;
          }
        } catch (e) {
          console.log('Error decrypting email for user ID:', row.id, e);
          continue;
        }
      }
    } catch (e) {
      console.log('Error in user search loop:', e);
    }

    if (!user) {
      console.log('Email not found');
      return res.status(400).send('Invalid email or password');
    }

    // Log the retrieved user
    console.log('Retrieved user:', user);

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.log('Password comparison error:', err);
        return res.status(400).send('Invalid email or password');
      }
      
      if (!result) {
        console.log('Password comparison failed');
        return res.status(400).send('Invalid email or password');
      }

      // Log successful password comparison
      console.log('Password comparison successful');

      try {
        const decryptedEmail = decryptData(user.email, user.password);
        const decryptedFatherName = decryptData(user.father_name, user.password);
        const decryptedFirstName = decryptData(user.first_name, user.password);
        const decryptedAddress = decryptData(user.address, user.password);
        const decryptedPhone = decryptData(user.phone, user.password);
        const decryptedRegNumber = decryptData(user.reg_number, user.password);
        
        // Handle passport_reg_number more carefully
        let decryptedPassportRegNumber = null;
        if (user.passport_reg_number) {
          try {
            decryptedPassportRegNumber = decryptData(user.passport_reg_number, user.password);
          } catch (e) {
            console.log('Error decrypting passport registration number:', e);
          }
        }

        // Log decrypted data
        console.log('Decrypted data:', {
          email: decryptedEmail,
          father_name: decryptedFatherName,
          first_name: decryptedFirstName,
          address: decryptedAddress,
          phone: decryptedPhone,
          reg_number: decryptedRegNumber,
          passport_reg_number: decryptedPassportRegNumber
        });

        res.status(200).json({
          email: decryptedEmail,
          father_name: decryptedFatherName,
          first_name: decryptedFirstName,
          address: decryptedAddress,
          phone: decryptedPhone,
          reg_number: decryptedRegNumber,
          passport_reg_number: decryptedPassportRegNumber
        });
      } catch (e) {
        console.log('Error decrypting user data:', e);
        return res.status(500).send('Error processing user data');
      }
    });
  });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
