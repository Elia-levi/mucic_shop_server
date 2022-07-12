const mongoose = require("mongoose");
const Joi = require("joi");

let categorySchema = new mongoose.Schema({
  name:String,
  short_id:String,
  url_name:String,
  img_url:String
})

exports.CategoryModel = mongoose.model("categories",categorySchema);

exports.validateCategory = (_bodyReq) => {
  let joiSchema = Joi.object({
    name:Joi.string().min(2).max(150).required(),
    url_name:Joi.string().min(3).max(100).required(),
    img_url:Joi.string().min(3).max(500).required()
  })
  return joiSchema.validate(_bodyReq);
}