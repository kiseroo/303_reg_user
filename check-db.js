const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Connect to the database
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

// Get table info
db.all(`PRAGMA table_info(users)`, (err, rows) => {
  if (err) {
    console.error('Error querying database schema:', err);
  } else {
    console.log('Table structure:');
    console.log(rows);
  }

  // Check if there are any records
  db.get(`SELECT COUNT(*) as count FROM users`, [], (err, row) => {
    if (err) {
      console.error('Error counting records:', err);
    } else {
      console.log(`Number of records in users table: ${row.count}`);
    }
    
    // Close the database
    db.close();
  });
});