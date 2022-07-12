const mongoose = require("mongoose");

const passwordResetSchema  = new mongoose.Schema({
  userId:String,
  resetString:String,
  createdat:Date,
  expiresAt:Date,
})

exports.PasswordResetModel  = mongoose.model("passwordReset ", passwordResetSchema );