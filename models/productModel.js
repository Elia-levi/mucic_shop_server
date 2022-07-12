const mongoose = require("mongoose");
const Joi = require("joi");

let productScheam =  new mongoose.Schema({
  name:String,
  info:String,
  price:Number,
  img_url:String,
  cat_short_id:String,
  date_created:{
    type:Date,default:Date.now()
  },

  user_id:String,
  // amount in the store of the product
  qty:{
    type:Number, default:1
  },
  short_id:String
})

exports.ProductModel = mongoose.model("products",productScheam);


exports.validateProduct = (_bodyReq) => {
  let joiSchema = Joi.object({
    name:Joi.string().min(2).max(150).required(),
    info:Joi.string().min(3).max(500).required(),
    price:Joi.number().min(1).max(999999).required(),
    cat_short_id:Joi.string().min(2).max(99).required(),
    img_url:Joi.string().min(3).max(500).required(),
    qty:Joi.number().min(1).max(9999).required(),

  })
  return joiSchema.validate(_bodyReq);
}