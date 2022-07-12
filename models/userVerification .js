const mongoose = require("mongoose");

const userSchemaVerification  = new mongoose.Schema({
  userId:String,
  uniqueString:String,
  createdat:Date,
  expiresAt:Date,
})

exports.UserModelVerification  = mongoose.model("usersVerification ", userSchemaVerification );