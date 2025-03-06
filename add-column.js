const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Connect to the database
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

// Add the missing column
db.run(`ALTER TABLE users ADD COLUMN passport_reg_number TEXT`, (err) => {
  if (err) {
    console.error('Error adding column:', err);
  } else {
    console.log('Successfully added passport_reg_number column to users table');
  }
  
  // Verify the table structure after the change
  db.all(`PRAGMA table_info(users)`, (err, rows) => {
    if (err) {
      console.error('Error querying table structure:', err);
    } else {
      console.log('Updated table structure:');
      console.log(rows);
    }
    
    db.close();
  });
});