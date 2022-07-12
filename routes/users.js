const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt")
const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");
const path = require("path")

const { validateUser, UserModel, validateLogin, genToken } = require("../models/userModel");
const { UserModelVerification } = require("../models/userVerification ");
const { auth, authAdmin } = require("../middlewares/auth");
const { config } = require("../config/secret");


// NEW
const { PasswordResetModel } = require("../models/passwordResetModel");
const { date } = require("joi");

// ========================================


let transporter = nodemailer.createTransport({
  host: "smtp-mail.outlook.com",
  secureConnection: false,
  port: 587,
  tls: {
    ciphers: 'SSLv3'
  },
  auth: {
    user: config.AUTH_EMAIL,
    pass: config.AUTH_PASS
  }
});


router.get("/", (req, res) => {
  res.json({ msg: "Users work" })
})

// Displays the entire list of users only to Adamin
router.get("/usersList", authAdmin, async (req, res) => {
  let perPage = req.query.perPage || 10;
  let page = req.query.page >= 1 ? req.query.page - 1 : 0;
  let sort = req.query.sort || "_id";
  let reverse = req.query.reverse == "yes" ? -1 : 1;
  try {
    let data = await UserModel.find({}, { password: 0 })
      .limit(perPage)
      .skip(page * perPage)
      .sort({ [sort]: reverse })
    res.json(data);
  }
  catch (err) {
    console.log(err);
    return res.status(500).json(err);
  }
})

// check if token of user valid and return info about the user if it admin or user
router.get("/checkUserToken", auth, async (req, res) => {
  res.json({ status: "ok", msg: "token is good", tokenData: req.tokenData })
})

// Displays only the information about a user and each user according to their token
router.get("/myInfo", auth, async (req, res) => {
  try {
    let data = await UserModel.findOne({ _id: req.tokenData._id }, { password: 0 })
    res.json(data);
  }
  catch (err) {
    console.log(err);
    return res.status(500).json(err);
  }
})

//give me the total amount of users in the collection of the db
router.get("/amount", async (req, res) => {
  try {
    let cat = req.query.cat || null
    objFind = (cat) ? { cat_short_id: cat } : {}
    // countDocuments -> return just the amount of documents in the collections
    let data = await UserModel.countDocuments(objFind);
    res.json({ amount: data });
  }
  catch (err) {
    console.log(err)
    res.status(500).json(err)
  }
})

// can change the role of user to admin or user , must be admin in this endpoint
router.patch("/changeRole/:userId/:role", authAdmin, async (req, res) => {
  let userId = req.params.userId;
  let role = req.params.role;
  try {
    //6299efbd79b22435397e0f61 -> user of super admin that cant change to regular user moshe user
    if (userId != req.tokenData._id && userId != "6299efbd79b22435397e0f61") {
      let data = await UserModel.updateOne({ _id: userId }, { role: role })
      res.json(data);
    }
    else {
      res.status(401).json({ err: "You cant change your self" });
    }
  }
  catch (err) {
    console.log(err);
    return res.status(500).json(err);
  }
})

// add new user
router.post("/", async (req, res) => {
  // check validate req.body
  let validBody = validateUser(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try {
    let user = new UserModel(req.body);
    user.password = await bcrypt.hash(user.password, 10);
    user.verified = false;
    await user.save();
    user.password = "*****";


    sendVerificationEmail(user, res);


  }
  catch (err) {
    if (err.code == 11000) {
      return res.status(400).json({ code: 11000, err: "Email already in system" })
    }
    console.log(err);
    return res.status(500).json(err);
  }
})

// login
router.post("/login", async (req, res) => {
  let validBody = validateLogin(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try {
    // check if there user with that email
    let user = await UserModel.findOne({ email: req.body.email })
    if (!user) {
      return res.status(401).json({ err: "User not found!" });
    }
    let validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) {
      return res.status(401).json({ err: "User or password is wrong" });
    }

    // NEW CHCK IF USER VERIFIED
    if (!user.verified) {
      return res.json({
        status: "FAILED",
        massage: "Email hesn't been verified yet. Check your inbox."
      });
    }

    // =====================================

    res.json({ token: genToken(user._id, user.role) });
  }
  catch (err) {
    console.log(err);
    return res.status(500).json(err);
  }
})

// Delete users
router.delete("/:idDelete", authAdmin, async (req, res) => {
  try {
    let idDelete = req.params.idDelete

    let data = await UserModel.deleteOne({ _id: idDelete });
    res.json(data);
  }
  catch (err) {
    console.log(err);
    return res.status(500).json(err);
  }
})



router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;
  UserModelVerification
    .find({ userId })
    .then((result) => {
      if (result.length > 0) {
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;


        if (expiresAt < Date.now()) {
          UserModelVerification
            .deleteOne({ userId })
            .then(result => {
              UserModel
                .deleteOne({ _id: userId })
                .then(() => {
                  let massage = "Link has expired. Please sign up again.";
                  res.redirect(`/users/verified/error=true&massage${massage}`)
                })
                .catch(error => {
                  let massage = "Clearing user with expired unuque string failed";
                  res.redirect(`/users/verified/error=true&massage${massage}`)
                })
            })
            .catch((error) => {
              console.log(error);
              let massage = "An error occurred while clearing expired user verification record";
              res.redirect(`/users/verified/error=true&massage${massage}`)
            })
        } else {
          // valid record exists so we validote the user string
          // first compare the hashed unique string

          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then(result => {
              if (result) {
                // string match

                UserModel
                  .updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserModelVerification
                      .deleteOne({ userId })
                      .then(() => {
                        res.sendFile(path.join(__dirname, "./../views/verified.html"));
                      })
                      .catch(error => {
                        console.log(error);
                        let massage = "An error occurred while finalizing successful verification.";
                        res.redirect(`/users/verified/error=true&massage${massage}`)
                      })
                  })
                  .catch(error => {
                    console.log(error);
                    let massage = "An error occurred while updating user record to show verified";
                    res.redirect(`/users/verified/error=true&massage${massage}`)
                  })
              } else {
                let massage = "Invalid verfication detals passed. Check your inbox.";
                res.redirect(`/users/verified/error=true&massage${massage}`)
              }
            })
            .catch(error => {
              let massage = "An error occurred while comparing unique strings";
              res.redirect(`/users/verified/error=true&massage${massage}`)
            })
        }
      } else {
        let massage = "Account record dosen't exist or hes been verified already. Please sigin up or log in.";
        res.redirect(`/users/verified/error=true&massage${massage}`)
      }
    })
    .catch((error) => {
      console.log(error);
      let massage = "An error occurred while checking for existing user verification record";
      res.redirect(`/users/verified/error=true&massage${massage}`)
    })
})

router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "./../views/verified.html"));
})


// password reset stuff
router.post("/requestPasswordReset", (req, res) => {
  const { email, redirectUrl } = req.body;

  // check if user is verified
  UserModel
    .find({ email })
    .then((data) => {
      if (data.length) {
        // user exists

        // check if user is verified

        if (!data[0].verified) {
          res.json({
            status: "FAILED",
            massage: "Email hesn't been verified yet. check your inbox.",
          })
        } else {
          // proceed with email to reset password
          sendResetEmail(data[0], redirectUrl, res)
        }
      } else {
        res.json({
          status: "FAILED",
          massage: "No account with the supplied email exists!",
        })
      }
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "FAILED",
        massage: "An error occurred while Checking for existing user",
      })
    })

})

// Actually reset the password
router.post("/resetPassword", (req, res) => {
  let { userId, resetString, newPassword } = req.body;

  PasswordResetModel
    .find({ userId })
    .then(result => {
      if (result.length > 0) {
        // password reset record exists so we proceed

        const { expiresAt } = result[0];
        const hashedResetString = result[0].resetString;
        // checkong for expired reset string
        if (expiresAt < Date.now()) {
          PasswordResetModel
            .deleteOne({ userId })
            .then(() => {
              // reset record deleted successfully
              res.json({
                status: "FAILED",
                massage: "Password reset link hes expired.",
              })
            })
            .catch(error => {
              // deletion failed
              console.log(error);
              res.json({
                status: "FAILED",
                massage: "Clearing password reset record failed.",
              });
            })
        } else {
          // valid reset record exists so we validate the resrt string first compore the hashed reset string

          bcrypt
            .compare(resetString, hashedResetString)
            .then((result) => {
              if (result) {
                // strings matched
                // hash password again

                const saltRounds = 10;
                bcrypt
                  .hash(newPassword,saltRounds)
                  .then(hashedNewPassword => {
                    // updote user password
                    UserModel
                      .updateOne({ _id: userId }, { password: hashedNewPassword })
                      .then(() => {
                        // Update complete. now delete reset record
                        PasswordResetModel
                          .deleteOne({ userId })
                          .then(() => {
                            // both user record and reset record updated
                            res.json({
                              status: "SUCCESS",
                              massage: "Password hes been reset successfully.",
                            })
                          })
                          .catch(error => {
                            console.log(error);
                            res.json({
                              status: "FAILED",
                              massage: "An error occurred while finalizing password reset.",
                            })
                          })
                      })
                      .catch(error => {
                        console.log(error);
                        res.json({
                          status: "FAILED",
                          massage: "Updating user password failed.",
                        })
                      })
                  })
                  .catch(error => {
                    console.log(error);
                    res.json({
                      status: "FAILED",
                      massage: "An error occurred while hashing new password",
                    })
                  })
              } else {
                // Existing record but incorrect reset string passed.
                res.json({
                  status: "FAILED",
                  massage: "Invalid password reset details passed.",
                })
              }
            })
            .catch(error => {
              res.json({
                status: "FAILED",
                massage: "Comparing password reset strings failed.",
              })
            })
        }
      } else {
        // password reset record dose't exist
        res.json({
          status: "FAILED",
          massage: "Password reset requst not found.",
        })
      }
    })
    .catch(error => {
      console.log(error);
      res.json({
        status: "FAILED",
        massage: "Checking for existing password reset record falied",
      })
    })
})


// Email sending Verification Email func
const sendVerificationEmail = ({ _id, email }, res) => {
  // need to change
  // const currentUrl = "http://localhost:3004/";
  const currentUrl = "https://musicsshop.herokuapp.com/";

  const uniqueString = uuidv4() + _id;

  const mailOptions = {
    from: config.AUTH_EMAIL,
    to: email,
    subject: "music shop verify your Email",
    html: `<p>verify your email address to complete the signup and login into your account.</p><p>This link <b>expires in 6 hours</b>.</p><p>Press <a href=${currentUrl + "users/verify/" + _id + "/" + uniqueString}>here </a>to proceed.</p>`,
  };

  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      const newVerification = new UserModelVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdat: Date.now(),
        expiresAt: Date.now() + 21600000,
      });
      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOptions)
            .then(() => {
              res.json({
                status: "PANDING",
                massage: "verification email sent",
              })
            })
            .catch((error) => {
              console.log(error)
              res.json({
                status: "FAILED",
                massage: "verification email failed ",
              })
            })
        })
        .catch((error) => {
          console.log(error)
          res.json({
            status: "FAILED",
            massage: "Couldn't save verification email data!",
          })
        })
    })
    .catch(() => {
      res.json({
        status: "FAILED",
        massage: "An error occurred while hashing email data!",
      });
    });
};

// send password reset email

const sendResetEmail = ({ _id, email }, redirectUrl, res) => {
  const resetString = uuidv4() + _id;

  // first, we clear all existing reset reccrds
  PasswordResetModel
    .deleteMany({ userId: _id })
    .then(result => {
      // reset records deleted successfully
      // now we send the email

      const mailOptions = {
        from: config.AUTH_EMAIL,
        to: email,
        subject: "Music Shop Password Reset",
        html: `<p>We heard that you lost the password.</p><p>Don't worry, use the link below to reset it.</p> <p>This link <b>expires in 60 minutes</b>.</p><p>Press <a href=${redirectUrl + "/" + _id + "/" + resetString}>here </a>to proceed.</p>`,
      };

      // hash the reset string
      const saltRounds = 10;
      bcrypt
        .hash(resetString, saltRounds)
        .then(hashedResetString => {
          // set valuse in password reset collection
          const newPasswordReset = new PasswordResetModel({
            userId: _id,
            resetString: hashedResetString,
            createdat: Date.now(),
            expiresAt: Date.now() + 3600000,
          });

          newPasswordReset
            .save()
            .then(() => {
              transporter
                .sendMail(mailOptions)
                .then(() => {
                  // reset email sent and password reser record saved
                  res.json({
                    status: "PANDING",
                    massage: "Password reset email sent",
                  })
                })
                .catch(error => {
                  console.log(error);
                  res.json({
                    status: "FAILED",
                    massage: "Password reset email failed ",
                  });
                })
            })
            .catch(error => {
              console.log(error)
              res.json({
                status: "FAILED",
                massage: "Couldn't save password reset data!",
              });
            })
        })
        .catch(error => {
          console.log(error)
          res.json({
            status: "FAILED",
            massage: "An error occurred while hashing the password reset data!",
          });
        });
    })
    .catch(error => {
      console.log(error)
      res.json({
        status: "FAILED",
        massage: "Clearing existing password reset records failed",
      });
    });
}



module.exports = router;