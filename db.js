var mysql = require('mysql');
var credentials = require('./config.js');
var pool = mysql.createPool(credentials);

//pool.connect();
pool.getConnection();

pool.query('SELECT 1 + 1 AS solution', function(error, results, fields) {
  if (error) throw error;
  console.log('The solution is: ', results[0].solution);
});

pool.end();

module.exports = connectDatabase();
