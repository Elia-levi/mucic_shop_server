const express = require("express");
const { auth } = require("../middlewares/auth");
const { ProductModel } = require("../models/productModel");
const { UserModel } = require("../models/userModel");
const router = express.Router();

// route thet manage the favorite products of user
// return the shorts_ids 
router.get("/", auth,async(req,res) => {
  try{
    let data = await UserModel.findOne({_id:req.tokenData._id})
    res.json({favs_ar:data.favs_ar || []})
  }
  catch(err){
    console.log(err);
    res.status(500).json(err)
  }
})

// retunr proudcts list by favorites that user choose
router.get("/productsInfo", auth,async(req,res) => {
  try{
    let data = await UserModel.findOne({_id:req.tokenData._id})
    let favs_ar = data.favs_ar || [];
    // get products list by favs_ar;
    let products = await ProductModel.find({short_id:{$in:favs_ar}})
    .limit(20)
    res.json(products)
  }
  catch(err){
    console.log(err);
    res.status(500).json(err)
  }
})

// add orremove product from favs_ar
router.patch("/add_remove/:prodId", auth, async(req,res) => {
  try{
    let prodId = req.params.prodId
    // get current favs_ar from user
    let user = await UserModel.findOne({_id:req.tokenData._id})
    let favs_ar = user.favs_ar || [];
    if(favs_ar.includes(prodId)){
      // remove the product from favorite_list of user (from favs_ar)
      favs_ar = favs_ar.filter(short_id => short_id != prodId)
    }
    else{
      // add in the start of the array
      favs_ar.unshift(prodId)
      // favorites of user cant save more than 40 products
      favs_ar.splice(40,favs_ar.length)
    }
    let data = await UserModel.updateOne({_id:req.tokenData._id},{favs_ar:favs_ar})
    res.json(data);
  }
  catch(err){
    console.log(err);
    res.status(500).json(err)
  }
})

module.exports = router;