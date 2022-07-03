const express = require("express");
const bcrypt = require("bcrypt")
const { validateUser, UserModel, validateLogin, genToken } = require("../models/userModel");
const { auth, authAdmin } = require("../middlewares/auth");
const router = express.Router();

router.get("/", (req, res) => {
  res.json({ msg: "Users work" })
})

// Displays the entire list of users only to Adamin
router.get("/usersList", authAdmin,async(req, res) => {
  let perPage = req.query.perPage || 10;
  let page = req.query.page >= 1 ? req.query.page - 1 : 0;
  try {
    let data = await UserModel.find({}, { password: 0 })
    .limit(perPage)
    .skip(page * perPage)
    res.json(data);
  }
  catch (err) {
    console.log(err);
    return res.status(500).json(err);
  }
})

// check if token of user valid and return info about the user if it admin or user
router.get("/checkUserToken", auth , async(req,res) => {
  res.json({status:"ok",msg:"token is good",tokenData:req.tokenData})
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
router.get("/amount", async(req,res) => {
  try{
    let cat = req.query.cat || null
    objFind = (cat) ? {cat_short_id:cat} : {}
    // countDocuments -> return just the amount of documents in the collections
    let data = await UserModel.countDocuments(objFind);
    res.json({amount:data});
  }
  catch(err){
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
    else{
      res.status(401).json({err:"You cant change your self"});
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
    await user.save();
    user.password = "*****";
    return res.status(201).json(user);
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
    res.json({ token: genToken(user._id, user.role) });
  }
  catch (err) {
    console.log(err);
    return res.status(500).json(err);
  }
})

// Delete users
router.delete("/:idDelete", authAdmin , async(req,res) => {
  try{
    let idDelete = req.params.idDelete
   
    let data = await UserModel.deleteOne({_id:idDelete});
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})


module.exports = router;