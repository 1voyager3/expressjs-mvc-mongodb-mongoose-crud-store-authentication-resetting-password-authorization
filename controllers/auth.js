// nodejs built-in lib, it helps to create secure unique random value
const crypto = require("crypto");

const bcrypt = require("bcryptjs");
// nodemailer is a package that makes sending emails from inside nodejs
const nodemailer = require("nodemailer");

// sendgrid is a package that helps with integrating sendgrid and
// conveniently use together with nodemailer
const sendgridTransport = require("nodemailer-sendgrid-transport");

const User = require("../models/user");

// initializing for nodemailer
const transporter = nodemailer.createTransport(sendgridTransport({
  auth: {
    // put appropriate sendgrid api_key
    api_key: ""
  }
}));

exports.getLogin = (req, res, next) => {

  let message = req.flash("error");

  if (message.length > 0) {
    message = message[0];
  } else (
      // to be rendered nothing
      message = null
  );

  console.log(req.flash("error"));

  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message
  });
};

exports.getSignup = (req, res, next) => {

  let message = req.flash("error");

  if (message.length > 0) {
    message = message[0];
  } else (
      // to be rendered nothing
      message = null
  );

  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message
  });
};

exports.postLogin = (req, res, next) => {

  const email = req.body.email;
  const password = req.body.password;

  // searching and comparing user by email
  User.findOne({ email: email })
      // if found the particular user by email then result will be searched user
      .then(user => {

        if (!user) {

          // providing User Feedback
          // using flash message in case if Email not found
          req.flash("error", "Invalid email or password!");

          return res.redirect("/login");
        }

        bcrypt.compare(password, user.password)
            .then(doMatch => {
              if (doMatch) {

                req.session.isLoggedIn = true;
                req.session.user = user;

                return req.session.save(err => {

                  console.log(err);

                  return res.redirect("/");
                });
              }

              // providing User Feedback
              // using flash message in case if Password not found
              req.flash("error", "Invalid email or password!");
              res.redirect("/login");
            })
            .catch(err => {
              console.log(err);
            });

      })
      .catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {

  // req.body.email === <input name="email"> in signup.ejs
  const email = req.body.email;

  // req.body.password === <input name="password"> in signup.ejs
  const password = req.body.password;

  // req.body.confirmPassword === <input name="confirmPassword"> in signup.ejs
  const confirmPassword = req.body.confirmPassword;

  User.findOne({ email: email })
      .then(userDoc => {

        if (userDoc) {

          req.flash("error", "E-mail exists already, please pick a different one!");
          return res.redirect("/signup");
        }

        return bcrypt
            .hash(password, 12)
            .then(hashedPassword => {

              const user = new User({
                email: email,
                password: hashedPassword,
                cart: { items: [] }
              });

              return user.save();
            })
            .then(result => {

              res.redirect("/login");

              return transporter.sendMail({
                to: email,
                from: "1voyagertest3@gmail.com",
                subject: "Test Signup",
                html: "<h1>Successfully Signed up!</h1>"
              });
            })
            .catch(err => {
              console.log(err);
            });
      })
      .catch(err => {
        console.log(err);
      });

};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);

    res.redirect("/");
  });
};

exports.getReset = (req, res, next) => {

  let message = req.flash("error");

  if (message.length > 0) {
    message = message[0];
  } else (
      // to be rendered nothing
      message = null
  );

  console.log(req.flash("error"));

  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message
  });
};

exports.postReset = (req, res, next) => {

  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);

      return res.redirect("/reset");
    }

    const token = buffer.toString("hex");

    // finding one User by email
    User.findOne({ email: req.body.email })
        .then(user => {

          if (!user) {
            req.flash("error", "No account with that email found!");
            return res.redirect("/reset");
          }

          // if user exists
          user.resetToken = token;
          // 3600000 ms / 1000 / 60 = 60 min = 1h
          user.resetTokenExpiration = Date.now() + 3600000;
          // to be updated in the database
          return user.save();

        })
        .then(result => {

          res.redirect("/");

          return transporter.sendMail({
            to: req.body.email,
            from: "1voyagertest3@gmail.com",
            subject: "Password Reset",
            html: `
            <p>You requested a password reset</p>
            <p>Click this <a href="http://localhost:3000/reset/${token}">link</a>to set a new password.</p>
            `
          });
        })
        .catch(err => {
          console.log(err);
        });
  });

};

exports.getNewPassword = (req, res, next) => {

  // router.get("/reset/:token", authController.getNewPassword);
  // req.params.token === "/reset/:token"
  const token = req.params.token;

  User.findOne({
    resetToken: token,
    // $gt stands for greater than
    resetTokenExpiration: { $gt: Date.now() }
  })
      .then(user => {
        let message = req.flash("error");

        if (message.length > 0) {
          message = message[0];
        } else (
            // to be rendered nothing
            message = null
        );

        console.log(req.flash("error"));

        res.render("auth/new-password", {
          path: "/new-password",
          pageTitle: "New Password",
          errorMessage: message,
          userId: user._id.toString(),
          passwordToken: token
        });

      })
      .catch(err => {
        console.log(err);
      });
};

exports.postNewPassword = (req, res, next) => {

  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;

  let resetUser;

  User.findOne({
    resetToken: passwordToken,
    // $gt stands for greater than
    resetTokenExpiration: { $gt: Date.now() }, _id: userId
  })
      .then(user => {
        resetUser = user;
        return bcrypt.hash(newPassword, 12);
      })
      .then(hashedPassword => {

        resetUser.password = hashedPassword;
        resetUser.resetToken = undefined;
        resetUser.resetTokenExpiration = undefined;

        return resetUser.save();

      })
      .then(result => {
        res.redirect("/login");
      })
      .catch(err => {
        console.log(err);
      });

};



