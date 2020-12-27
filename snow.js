//jshint esversion:6
/*Required files*/
require("dotenv").config();

const express = require("express");

/**/
var credentials = require("./config.js");
var session = require("express-session");
var MySQLStore = require("express-mysql-session")(session);
var sessionStore = new MySQLStore(credentials);
var cookieParser = require("cookie-parser");
/**/

const bodyParser = require("body-parser");
const ejs = require("ejs");
const dateFormat = require("dateformat");

const general = require("./routes/general");
//const admin = require("./routes/admin");
//const parks = require("./routes/parks");
//const customer = require("./routes/customer");
//const security = require("./routes/security");
//const search = require("./routes/search");

const app = express();

const server = require("http").createServer(app);
const url = require("url");
/*Required files*/


/*Required files*/
//app.use(express.static(__dirname + "/public"));
app.use(express.static(__dirname + "/public"));
//app.use(express.static(__dirname + "public_snow_tracker"));
//app.use(express.static('./public_html/'));
//app.use(express.static('/public_snow_tracker'));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
/*Required files*/


//Password protect middleware
/*app.use((req, res, next) => {

  // -----------------------------------------------------------------------
  // authentication middleware

  const auth = {login: 'parks_92', password: '5s9aqRSS")pjJ)WJ'} // change this

  // parse login and password from headers
  const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
  const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':')

  // Verify login and password are set and correct
  if (login && password && login === auth.login && password === auth.password) {
    // Access granted...
    return next()
  }

  // Access denied...
  res.set('WWW-Authenticate', 'Basic realm="401"') // change this
  res.status(401).send('Authentication required.') // custom message

  // -----------------------------------------------------------------------

})*/

var sessionMiddleware = session({
  key: "user_sid",
  secret: "somerandonstuffs",
  store: sessionStore,
  resave: false,
  saveUninitialized: true,
  maxAge: null,
  /*cookie: {
    expires: 1500000
  }*/
});


app.use(sessionMiddleware);

app.use(cookieParser());

app.use("/", general, sessionMiddleware);

/*Port listener*/
server.listen(process.env.PORT || 3000, function () {
  console.log("Server started on port 3000");
});
/*Port listener*/
