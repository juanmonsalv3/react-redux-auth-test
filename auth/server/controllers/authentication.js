const jwt = require("jwt-simple");
const config = require("../config");
const User = require("../models/user");

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

module.exports.login = function (req, res) {
  res.send({ token: tokenForUser(req.user) });
};

module.exports.signup = function (req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res
      .status(422)
      .send({ error: "You must provide email and password" });
  }

  User.findOne({ email: email }, function (err, existingUser) {
    if (err) {
      return next(err);
    }

    // if a user with email does exist, return an error
    if (existingUser) {
      return res.status(422).send({ error: "Email is in use" });
    }

    // if user with that email does not exist, create and save user record

    const user = new User({
      email: email,
      password: password,
    });
    user.save(function (err) {
      if (err) {
        return next(err);
      }

      //respond to request indicating user was created
      res.json({ token: tokenForUser(user) });
    });
  });
};
