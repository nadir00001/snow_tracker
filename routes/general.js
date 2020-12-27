const bcrypt = require("bcrypt");
const express = require('express');
const controllers = require('../controllers/general');
const multer = require('multer');
const path = require('path');
const router = express.Router();

function makeid(length) {
  var result = '';
  var characters = '-~!@ABCDEFGHIJKLMNOPQRSTUVWXYZ-~!@abcdefghijklmnopqrstuvwxyz0123456789$-~!@';
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}


/*GET*/

//router.get("/instances", controllers.displayIndex);
router.get("/", controllers.displayIndex);
router.get("/register", controllers.displayRegister);
router.get("/login", controllers.displayLogin);
router.get("/add_instance", controllers.displayAddInstance);
router.get("/logout", controllers.logout);

/*GET*/

/*POST*/

router.post("/add_instance", controllers.addInstance);
router.post("/relaunch_instance/:instance_id", controllers.relaunchInstance);
router.post("/remove_instance/:instance_id", controllers.removeInstance);
router.post("/register", controllers.register);
router.post("/login", controllers.login);


//router.post("/register", controllers.registerUser);

/*POST*/

module.exports = router;
