const mongoose = require("mongoose");
const Joi = require("joi");

const orderSchema = new mongoose.Schema({
  // products_ar = [{s_id:,amount:,price:}]
  products_ar:{
    type:Array, default:[]
  },
  user_id:String,
  
  // pending,paid, shipped, completed
  status:{
    type:String, default:"pending"
  },
  total_price:Number,
  date_created:{
    type:Date,default:Date.now()
  },
  name:String,
  address:String,
  phone:String,
  email:String
})

exports.OrderModel = mongoose.model("orders",orderSchema);

exports.validateOrder = (_bodyReq) => {
  let joiScehma = Joi.object({
    products_ar: Joi.array().min(1).max(999).required(),
    total_price:Joi.number().min(1).max(999999).required(),
  })
  return joiScehma.validate(_bodyReq);
}