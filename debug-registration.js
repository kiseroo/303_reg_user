const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Helper function to encrypt data
function encryptData(data, password) {
  const key = crypto.createHash('sha256').update(password).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Connect to the database
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

// Test data
const testUser = {
  email: 'test@example.com',
  password: 'password123',
  father_name: 'TestFather',
  first_name: 'TestUser',
  address: 'Test Address',
  phone: '1234567890',
  passport_reg_number: 'TEST123'
};

// Generate a registration number
db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
  if (err) {
    console.error('Error generating registration number:', err);
    return;
  }
    
  // Create a new registration number
  const count = row ? row.count + 1 : 1;
  const reg_number = `#${count}`;
  
  console.log(`Generated registration number: ${reg_number}`);

  // Hash the password
  bcrypt.hash(testUser.password, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password:', err);
      return;
    }

    console.log('Password hashed successfully');

    try {
      // Encrypt user data
      const encryptedEmail = encryptData(testUser.email, hashedPassword);
      const encryptedFatherName = encryptData(testUser.father_name, hashedPassword);
      const encryptedFirstName = encryptData(testUser.first_name, hashedPassword);
      const encryptedAddress = encryptData(testUser.address, hashedPassword);
      const encryptedPhone = encryptData(testUser.phone, hashedPassword);
      const encryptedRegNumber = encryptData(reg_number, hashedPassword);
      
      // Handle passport_reg_number carefully
      let encryptedPassportRegNumber = null;
      if (testUser.passport_reg_number) {
        encryptedPassportRegNumber = encryptData(testUser.passport_reg_number, hashedPassword);
      }

      console.log('Data encrypted successfully');
      
      // Insert the test user into the database
      const stmt = db.prepare(`INSERT INTO users (
        email, password, father_name, first_name, address, phone, reg_number, passport_reg_number
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
      
      stmt.run(
        encryptedEmail,
        hashedPassword,
        encryptedFatherName,
        encryptedFirstName,
        encryptedAddress,
        encryptedPhone,
        encryptedRegNumber,
        encryptedPassportRegNumber,
        function(err) {
          if (err) {
            console.error('Error inserting user:', err);
          } else {
            console.log(`User inserted successfully with ID: ${this.lastID}`);
          }
          
          stmt.finalize();
          db.close();
        }
      );
    } catch (error) {
      console.error('Error during encryption or insertion:', error);
      db.close();
    }
  });
});