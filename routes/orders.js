const express = require("express");
const { auth, authAdmin, payPalAuth } = require("../middlewares/auth");
const { validateOrder, OrderModel } = require("../models/orderModel");
const { ProductModel } = require("../models/productModel");
const { UserModel } = require("../models/userModel");
const router = express.Router();

router.get("/", (req,res) => {
  res.json({msg:"Orders work"})
})

// route of admin get all orders
router.get("/allOrders", authAdmin, async(req,res) => {
  let perPage = req.query.perPage ||10;
  let page = req.query.page >= 1 ? req.query.page - 1 : 0;
  let sort = req.query.sort || "_id";
  let reverse = req.query.reverse == "yes" ? -1 : 1;
  let user_id = req.query.user_id;
  
  try{
    let filter = user_id ? {user_id:user_id} : {}
    let data = await OrderModel.find(filter)
    .limit(perPage)
    .skip(page * perPage)
    .sort({[sort]:reverse})
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

//give me the total order of subCategory in the collection of the db
router.get("/allOrdersCount" , auth , async(req,res) => {
  try{
    let amount = await OrderModel.countDocuments({});
    res.json({amount})
  }
  catch(err){ 
    console.log(err);
    return res.status(500).json(err);
  }
})

// route get user orders
router.get("/userOrder", auth , async(req,res) => {
  try{
    let data = await OrderModel.find({user_id:req.tokenData._id})
    .limit(20)
    .sort({_id:-1})
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

// get info about products in single order by order id
router.get("/productsInfo/:idOrder", auth,async(req,res) => {
  try{
    let order = await OrderModel.findOne({_id:req.params.idOrder});
    // prodShortIds_ar = [33213,12211]
    let prodShortIds_ar = order.products_ar.map(item => item.s_id);
    let products = await ProductModel.find({short_id:{$in:prodShortIds_ar}})
    // return also the products query, and the order query
    res.json({products,order});
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

// route add new order
router.post("/", auth, async(req,res) => {
  let validBody = validateOrder(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try{
    // get data from user
    let user = await UserModel.findOne({_id:req.tokenData._id});
// add new props to the body before save or update
    req.body.name = user.name;
    req.body.address = user.address;
    req.body.phone = user.phone;
    req.body.email = user.email;


    // check if there already order of the same user that pending
    let order = await OrderModel.findOne({user_id:req.tokenData._id,status:"pending"})

    // TODO: check if id of product equal to price that sending
    if(order){
      // update 
      let data = await OrderModel.updateOne({_id:order._id},req.body)
      return res.json(data)
    }
    // add new order
    let newOrder = new OrderModel(req.body);
    newOrder.user_id = req.tokenData._id;
    await newOrder.save()
    return res.status(201).json(newOrder);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

// update for client user the status of order
router.patch("/orderPaid/", auth ,  async(req,res) => {
 
  // let orderId = req.params.orderId;
  try{
    // 0. check if paypal really do the transction with token and orderID
    let tokenId = req.body.tokenId;
    let orderId = req.body.orderId;
    let realPay = (req.body.realPay == "yes") // false or true
    let paypalData = await payPalAuth(tokenId,orderId,realPay)
    if(paypalData.status != "COMPLETED"){
      return res.status(401).json({err_msg:"There problem in the payment"})
    }
    // 1. find the id of the current order by pendinf and user_id
    let currentOrder = await OrderModel.findOne({status:"pending", user_id:req.tokenData._id})
    let shortProds_ids = currentOrder.products_ar.map(item => {
      return item.s_id
    })
    // 2. get array of all products
    let prods_ar = await ProductModel.find({short_id:{$in:shortProds_ids}})
    // loop on all products and
    prods_ar.forEach(async(item) => {
    // update the products qty in -1
      item.qty -= 1;
      let prodUpdate = await ProductModel.updateOne({_id:item._id},item)
    })
    let status = "paid ";
    let data = await OrderModel.updateOne({status: "pending", user_id:req.tokenData._id},{status})
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

// route update order status
// ?status = 
router.patch("/:orderId", authAdmin ,  async(req,res) => {
  let status = req.query.status || "pending";
  let orderId = req.params.orderId;
  try{
    let data = await OrderModel.updateOne({_id:orderId},{status})
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

// route delete order
router.delete("/:delId", authAdmin ,  async(req,res) => {
  let orderId = req.params.delId;
  try{
    let data = await OrderModel.deleteOne({_id:orderId})
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})



module.exports = router;