require('dotenv').config();
var credentials = {
  host: process.env.LOCAL_HOST,
  database: process.env.LOCAL_DB,
  user: process.env.LOCAL_USER,
  password: process.env.LOCAL_PASS
};
module.exports = credentials;
