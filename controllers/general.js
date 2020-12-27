require("dotenv").config();
const bcrypt = require("bcrypt");

const mysql = require("mysql");
//const puppeteer = require('puppeteer');
const {
  chromium
} = require('playwright');

var credentials = require("../config.js");
var pool = mysql.createPool(credentials);

var util = require("util");

var crypto = require('crypto');
var algorithm = process.env.ALGORITHM;
const key = process.env.CRYPTO_KEY;

chromeFinder = require('chrome-finder')

//const chromium = require('chromium');
const path = require('path');

var errors = [];
var messages = [];
var loading = "";
var today = new Date();
var user_info = [];
const dateFormat = require("dateformat");
dateFormat.i18n = {
  dayNames: [
    "Dim",
    "Lun",
    "Mar",
    "Mer",
    "Jeu",
    "Ven",
    "Sam",
    "Dimanche",
    "Lundi",
    "Mardi",
    "Mercredi",
    "Jeudi",
    "Vendredi",
    "Samedi",
  ],
  monthNames: [
    "Jan",
    "Fév",
    "Mar",
    "Avr",
    "Mai",
    "Juin",
    "Juill",
    "Aou",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
    "Janvier",
    "Février",
    "Mars",
    "Avril ",
    "Mai",
    "Juin",
    "Juillet",
    "Août",
    "Septembre",
    "Octobre",
    "Novembre",
    "Décembre",
  ],
  timeNames: ["a", "p", "am", "pm", "A", "P", "AM", "PM"],
};

exports.displayIndex = (req, res, next) => {

  if (req.session.logedin && req.cookies.user_sid) {

    var user_id = req.session.user_id;

    var ready = "SELECT * FROM instances WHERE user_id = ?";
    var clean_data = [];

    pool
      .query(ready, [user_id])
      .then((data) => {
        //console.log(data);

        for (i = 0; data.length > i; i++) {
          var date = "";
          var day_left = "";
          if (data[i].last_login_db) {
            date = dateFormat(data[i].last_login_db, "dd/mm/yyyy");
            var date1 = new Date(data[i].last_login_db);
            var date2 = new Date(today);
            var Difference_In_Time = date2.getTime() - date1.getTime();
            var Difference_In_Days = Difference_In_Time / (1000 * 3600 * 24);
            day_left = Math.ceil(10 - Difference_In_Days);
          } else {
            date = "N/A";
            day_left = "N/A";
          }

          clean_data.push({
            id: data[i].id,
            instance_email: data[i].instance_email,
            instance: data[i].instance,
            //day_left: data[i].day_left,
            day_left: day_left,
            last_login_db: date,
          });

        }

        //console.log(JSON.stringify(data));
        //console.log(JSON.stringify(clean_data));

        res.render("home", {
          instances: clean_data,
          errors: errors,
          messages: messages,
          loading: loading,
        });
        errors = [];
        messages = [];
      })
      .catch((err) => {
        console.log(err);
      });

  } else {
    res.redirect("/login");
  }

}

exports.displayRegister = (req, res, next) => {

  if (req.session.logedin && req.cookies.user_sid) {
    res.redirect("/");
  } else {
    res.render("register", {
      errors: errors,
      messages: messages,
    });
    errors = [];
    messages = [];
  }

}

exports.register = (req, res, next) => {

  let first_name = req.body.first_name;
  let last_name = req.body.last_name;
  let username = req.body.username;
  let email = req.body.email;

  process.env.SECRET = bcrypt.hashSync(
    req.body.password,
    bcrypt.genSaltSync(9)
  );

  let check_username = "SELECT * FROM users WHERE username = ?";
  let check_email = "SELECT * FROM users WHERE email = ?";
  let insert_user = "INSERT INTO users (username, first_name, last_name, email,password) VALUES ( ? , ? , ?, ? , ?)";
  let username_arr = [];
  let email_arr = [];
  pool.query(check_username, [username])
    .then(rows => {
      username_arr = rows;
      return pool.query(check_email, [email]);
    })
    .then(rows => {
      email_arr = rows;
    })
    .then(() => {
      console.log("user_arr = " + JSON.stringify(username_arr));
      console.log("email_arr = " + JSON.stringify(email_arr));

      if (username_arr.length > 0 && username_arr[0].username == username) {
        errors.push("This username : " + username + " is already taken please select a new one.");
      }
      if (email_arr.length > 0 && email_arr[0].email == email) {
        errors.push("This email : " + email + " is already taken please select a new one.");
      }
      if (errors.length === 0) {
        pool.query(insert_user, [username, first_name, last_name, email, process.env.SECRET])
        messages.push("Your account has been successfully created !");
        res.redirect("/login");
      } else {
        res.redirect("/register");
        return false;
      }
    }).catch(err => {
      console.log(err);
      errors.push("An error occured during the process please try again later.");
      res.redirect("/register")
    });

}

exports.displayLogin = (req, res, next) => {

  if (req.session.logedin && req.cookies.user_sid) {
    res.redirect("/");
  } else {
    res.render("login", {
      errors: errors,
      messages: messages,
    });
    errors = [];
    messages = [];
  }

}

exports.login = (req, res, next) => {

  if (req.session.logedin === true) {
    res.redirect("/");
  } else {
    let username = req.body.username;
    let password = req.body.password;
    req.session.logedin = false;

    let user = [];
    let check_username = "SELECT * FROM users WHERE username = ? "
    pool.query(check_username, [username])
      .then((result) => {
        user = result;
      })
      .then(() => {
        if (user.length == 0) {
          errors.push("Ce nom d'utilisateur n'existe pas chez nous");
        } else if (!bcrypt.compareSync(password, user[0].password)) {
          errors.push("Le mot de passe que tu as saisi est incorrect");
        }
        /*else if (usernames[0].email_conf == "false") {
        errors.push(
        "Vous ne pouvez pas vous connecter tant que vous n'avez pas confirmé votre adresse email"
        );
        }*/
        if (errors.length > 0) {
          /*res.render("login", {
          errors: errors,
          messages: messages,
          });
          errors = [];
          messages = [];*/
          res.redirect("/login");
        } else if (bcrypt.compareSync(password, user[0].password) && req.session.logedin != true) {

          var sess = req.session; //initialize session variable
          req.session.logedin = true;
          req.session.full_name = user[0].first_name + " " + user[0].last_name;
          req.session.username = user[0].username;
          req.session.user_id = user[0].id;
          //req.session.profile_pic = user[0].profile_picture;
          //req.session.user_type = user[0].user_type;
          //req.session.ready = user[0].ready;
          /*if (mandatory_documents.indexOf(null) > -1 && req.session.user_type == "parks") {
          req.session.ready = "false";
          } else {
          req.session.ready = "true";
          }*/
          res.redirect("/");
          //res.redirect(req.session.returnTo || "/");
          //delete req.session.returnTo;
        }
      })
      .catch((err) => {
        console.log(err);
        res.redirect("/login");
      });
  }


}

exports.displayAddInstance = (req, res, next) => {

  if (req.session.logedin && req.cookies.user_sid) {
    res.render("add_instance", {
      errors: errors,
      messages: messages,
    });
    errors = [];
    messages = [];
  } else {
    res.redirect("/login");
  }

}

exports.addInstance = (req, res, next) => {

  //let first_name = 'Nadir';
  //let last_name = 'Hamada';
  let user_id = req.session.user_id;
  let instance = req.body.instance;
  let instance_email = req.body.instance_email;
  //let instance_password = req.body.instance_password;
  //let instance_password_conf = req.body.instance_password_conf;
  //let password = '';
  //let snow_username = '';
  //let snow_password = '';
  //let last_login_db = '';
  //let day_left = '';

  /*Not crypted*/
  //process.env.SECRET = encrypt(req.body.instance_password);
  process.env.SECRET = encrypto.encrypt(req.body.instance_password, key)
  //console.log("PASSWORD = " + process.env.SECRET);
  //process.env.SECRET_CONF = encrypt(req.body.instance_password_conf);
  process.env.SECRET_CONF = encrypto.encrypt(req.body.instance_password_conf, key)
  //console.log("PASSWORD = " + process.env.SECRET_CONF);
  /*Not crypted*/

  let check_instance = "SELECT * FROM instances WHERE instance = ?";
  let insert_new_instance = "INSERT INTO instances (user_id, instance, instance_email,instance_password) VALUES ( ? , ? , ?, ?)";
  let instances_results = [];
  pool.query(check_instance, [instance])
    .then(rows => {
      instances_results = rows;
    })
    .then(() => {

      //console.log("Instances = " + JSON.stringify(instances_results));

      if (instances_results.length > 0) {
        errors.push("Instance " + instances_results[0].instance + " already exists please enter a new instance.");
        res.redirect("/add_instance");
        return false;
      }
      if (process.env.SECRET != process.env.SECRET_CONF) {
        errors.push("The passwords are not matching please try again !");
        res.redirect("/add_instance");
        return false;
      } else {

        pool.query(insert_new_instance, [user_id, instance, instance_email, process.env.SECRET])
        messages.push("Your instance has been successfully added !");
        res.redirect("/");
      }

    }).catch(err => {
      console.log(err);
      errors.push("An error occured during the process please try again later.");
      res.redirect("/add_instance")
    });
}

exports.relaunchInstance = async (req, res, next) => {

  let instance_email;
  let instance_password;

  var ready = "SELECT * FROM instances WHERE instance = ?";
  var update = "UPDATE instances SET last_login_db = ?, day_left = ? WHERE instance = ?;";

  let retrieved_instance = req.params.instance_id;

  let rows = await new Promise((resolve, reject) => {
    pool.query(ready, [retrieved_instance], function(err, rows) {
      if (err) {
        console.log(err);
        reject(err);
      } else {
        //console.log('DB insert successful. Record: ' + i);
        resolve(rows);
      }
    });
  });

  instance_email = rows[0].instance_email;
  process.env.SECRET = encrypto.decrypt(rows[0].instance_password, key)

  const scraperData = await scrapper(instance_email, process.env.SECRET);

  var a = "";

  if (scraperData.login == 'success') {

    if (scraperData.instance_awake == "true") {
      a = "awake, you can access instance " + retrieved_instance + " clicking on the instance id in the table below";
    } else {
      a = "sleeping, we awaked it for you ! Now chill for max 1mn before accessing instance " + retrieved_instance;
    }

    var sentence = "Your instance was " + a;
    messages.push(sentence);

    let update_instance = await new Promise((resolve, reject) => {
      pool.query(update, [today, 10, retrieved_instance], function(err, rows) {
        if (err) {
          console.log(err);
          reject(err);
        } else {
          console.log('DB updated successfully');
          resolve(rows);
        }
      });
    });

  } else if (scraperData.login == 'fail') {

    errors.push("The email or the password you provided are wrong please try to connect manually and correct the email or password. Then try again !");

  } else {

    errors.push("Something went wrong during the update please check the FAQ in order to fix it.");

  }

  res.redirect("/")

}

exports.removeInstance = (req, res, next) => {

  let instance = req.params.instance_id;

  let delete_instance = "DELETE FROM instances WHERE instance = ?";
  let get_user_info = "SELECT * FROM users WHERE id = ?";
  let user = [];
  pool.query(get_user_info, [1])
    .then(rows => {
      rows = user;
    })
    .then(() => {
      pool.query(delete_instance, [instance])
      messages.push("Your instance has been successfully deleted !");
      res.redirect("/");
    }).catch(err => {
      console.log(err);
      errors.push("An error occured during the process please try again later.");
      res.redirect("/")
    });
};

exports.logout = (req, res) => {
  res.clearCookie("user_sid");
  res.redirect("/login");
};

pool.on('acquire', function(connection) {
  console.log('Connection %d acquired', connection.threadId);
});

pool.on('release', function(connection) {
  console.log('Connection %d released', connection.threadId);
});

pool.on('connection', function(connection) {
  connection.query('SET SESSION auto_increment_increment=1')
});

pool.on('enqueue', function() {
  console.log('Waiting for available connection slot');
});

const chromeOptions = {
  ignoreHTTPSErrors: true,
  args: [
    '--ignore-certificate-errors',
    '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',
  ]
};

async function scrapper(instance_email, instance_password) {
  const browser = await chromium.launch(chromeOptions);
  const page = await browser.newPage();
  await page.goto('https://signon.service-now.com/ssologin.do?RelayState=%252Fapp%252Ftemplate_saml_2_0%252Fk317zlfESMUHAFZFXMVB%252Fsso%252Fsaml%253FRelayState%253Dhttps%25253A%25252F%25252Fdeveloper.servicenow.com%25252Fsaml_redirector.do%25253Fsysparm_nostack%25253Dtrue%252526sysparm_uri%25253D%2525252Fnav_to.do%2525253Furi%2525253D%252525252Fssologin.do%252525253FrelayState%252525253Dhttps%25252525253A%25252525252F%25252525252Fdeveloper.servicenow.com%25252525252Fdev.do&redirectUri=&email=', {
    waitUntil: 'domcontentloaded'
  });
  await page.waitForSelector("#username");
  await page.fill('#username', instance_email)
  await page.click('#usernameSubmitButton')
  await page.fill('#password', instance_password)
  await page.click('#submitButton')
  //await page.waitForSelector("dps-app");

  await delay(15000);

  /**/
  const output = await page.evaluate(() => {

    var dpsApp = document.querySelector("dps-app");

    var answer = {};

    if (dpsApp) {

      answer.login = "success";

      var days_left_elements = document.querySelector("dps-app").shadowRoot.querySelector("dps-home-auth").shadowRoot.querySelector("dps-instance-sidebar").shadowRoot.querySelectorAll(".dps-instance-sidebar-content-instance-info-text")
      var days_left = "";
      var release = "";
      var element = "";

      for (x = 0; days_left_elements.length > x; x++) {
        element = days_left_elements[x].innerText;
        if (element.indexOf("days") > -1) {
          days_left = element;
          answer.days_left = days_left;
        } else {
          release = element;
          answer.release = release;
        }
      }

      var target_buttons = document.querySelector("dps-app").shadowRoot.querySelector("dps-home-auth").shadowRoot.querySelector("dps-instance-sidebar").shadowRoot.querySelectorAll("dps-button");

      for (var y = 0; target_buttons.length > y; y++) {
        var button = target_buttons[y].shadowRoot.querySelector('button');
        var button_text = target_buttons[y].shadowRoot.querySelector('button').innerText;
        //Wake Instance
        if (button_text.indexOf("Wake Instance") > -1) {
          answer.instance_awake = "false";
          break;
          //button.click();
          //target_buttons[0].shadowRoot.querySelector('button').click();
        }
      }

      /*if (!answer.instance_awake) {
              answer.instance_awake = "true";
            }*/


    } else {

      answer.login = "fail";

    }

    //Break the loading when awake instance
    //window.location.replace("https://www.google.fr/");

    return answer;
  });

  //await console.log("OUTPUT = " + JSON.stringify(output));

  if (output.instance_awake == "false") {

    await page.evaluate(() => {

      var target_buttons = document.querySelector("dps-app").shadowRoot.querySelector("dps-home-auth").shadowRoot.querySelector("dps-instance-sidebar").shadowRoot.querySelectorAll("dps-button");
      target_buttons[0].shadowRoot.querySelector('button').click();

      /*for (var y = 0; target_buttons.length > y; y++) {
          var button = target_buttons[y].shadowRoot.querySelector('button');
          var button_text = target_buttons[y].shadowRoot.querySelector('button').innerText;
          //Wake Instance
          if (button_text.indexOf("Wake Instance") > -1) {
            button.click();
          }
      }*/
    })
  } else {

    output.instance_awake = "true";
  }

  await browser.close();

  return output;
}

async function buildMessages(scraperData) {
  var a = "";

  if (scraperData.login == 'success') {

    if (scraperData.instance_awake == "true") {
      a = "awake, you can access instance " + retrieved_instance + " clicking on the instance id in the table below";
    } else {
      a = "sleeping, we awaked it for you ! Now chill for max 1mn before accessing instance " + retrieved_instance;
    }

    var sentence = "Your instance was " + a;
    messages.push(sentence);

    let update_instance = await new Promise((resolve, reject) => {
      pool.query(update, [today, 10, retrieved_instance], function(err, rows) {
        if (err) {
          console.log(err);
          reject(err);
        } else {
          console.log('DB updated successfully');
          resolve(rows);
        }
      });
    });

  } else if (scraperData.login == 'fail') {

    errors.push("The email or the password you provided are wrong please try to connect manually and correct the email or password. Then try again !");

  } else {

    errors.push("Something went wrong during the update please check the FAQ in order to fix it.");

  }
}

function delay(time) {
  return new Promise(function(resolve) {
    setTimeout(resolve, time)
  });
}

const encrypto = {

  encrypt(text, password) {
    const key = password.repeat(32).substr(0, 32)
    const iv = password.repeat(16).substr(0, 16)
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv)
    let encrypted = cipher.update(text, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    return encrypted
  },

  decrypt(text, password) {
    console.log("TEXT = " + text);
    console.log("KEY = " + password);
    const key = password.repeat(32).substr(0, 32)
    const iv = password.repeat(16).substr(0, 16)
    const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv)
    let decrypted = decipher.update(text, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }

}

pool.query = util.promisify(pool.query);
