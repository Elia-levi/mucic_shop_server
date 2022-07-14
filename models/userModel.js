const mongoose = require("mongoose");
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const { config } = require("../config/secret");

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  img_user:String,
  role: {
    type: String, default: "user"
  },
  create_date: {
    type: Date, default: Date.now()
  },
  address: String,
  phone: String,
  verified: Boolean,
  favs_ar: {
    type: Array, default: []
  }
})

exports.UserModel = mongoose.model("users", userSchema);

exports.genToken = (_userId, _role) => {
  let token = jwt.sign({ _id: _userId, role: _role }, config.tokenSecret, { expiresIn: "600mins" });
  return token;
}

exports.validateUser = (_bodyReq) => {
  let joiSchema = Joi.object({
    name: Joi.string().min(2).max(100).required(),
    email: Joi.string().min(2).max(150).email().required(),
    password: Joi.string().min(3).max(100).required(),
    address: Joi.string().min(2).max(300).required(),
    phone: Joi.string().min(2).max(300).required(),
    img_user:Joi.string().min(3).max(1000).allow(null,""),
  })
  return joiSchema.validate(_bodyReq);
}

exports.validateLogin = (_bodyReq) => {
  let joiSchema = Joi.object({
    email: Joi.string().min(2).max(150).email().required(),
    password: Joi.string().min(3).max(100).required(),
  })
  return joiSchema.validate(_bodyReq);
}