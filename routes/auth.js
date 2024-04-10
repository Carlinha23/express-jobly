"use strict";

/** Routes for authentication. */

const jsonschema = require("jsonschema");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');

const User = require("../models/user");
const express = require("express");
const router = new express.Router();
const { createToken } = require("../helpers/tokens");
const userAuthSchema = require("../schemas/userAuth.json");
const userRegisterSchema = require("../schemas/userRegister.json");
const { BadRequestError } = require("../expressError");

const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { ensureLoggedIn } = require("../middleware/auth");
//const User = require('../models/user'); // Adjust the path as needed

/** POST /auth/token:  { username, password } => { token }
 *
 * Returns JWT token which can be used to authenticate further requests.
 *
 * Authorization required: none
 */
router.get('/', (req, res, next) => {
  res.send("APP IS WORKING!!!")
})

router.post("/token", async function (req, res, next) {
  try {
    const validator = jsonschema.validate(req.body, userAuthSchema);
    if (!validator.valid) {
      const errs = validator.errors.map(e => e.stack);
      throw new BadRequestError(errs);
    }

    const { username, password } = req.body;
    const user = await User.authenticate(username, password);
    const token = createToken(user);
    return res.json({ token });
  } catch (err) {
    return next(err);
  }
});


/** POST /auth/register:   { user } => { token }
 *
 * user must include { username, password, firstName, lastName, email }
 *
 * Returns JWT token which can be used to authenticate further requests.
 *
 * Authorization required: none
 */

router.post('/register', async (req, res, next) => {
  try {
    const { username, password, first_name, last_name, email, is_admin } = req.body;
    if (!username || !password || !first_name || !last_name || !email || !is_admin) {
      throw new ExpressError("All fields are required", 400);
    }
    // hash password
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    // save to db
    const results = await db.query(`
      INSERT INTO users (username, password, firstName, lastName, email, is_admin)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING username`,
      [username, hashedPassword, first_name, last_name, email, is_admin]);
    
    return res.json(results.rows[0]);
  } catch (e) {
    if (e.code === '23505') {
      return next(new ExpressError("Username taken. Please pick another!", 400));
    }
    return next(e)
  }
});


module.exports = router;
