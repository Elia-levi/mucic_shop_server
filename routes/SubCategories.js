const express = require("express");
const {random} = require("lodash")
const { authAdmin } = require("../middlewares/auth");
const { ProductModel } = require("../models/productModel");
const { SubCategoriesModel,validateSubCategories } = require("../models/SubCategoriesModel");
const router = express.Router();

// Displays all subcategories with filter option
//?cat= let you get subcategories of one category by its short_id
router.get("/", async(req,res) => {
  let perPage = req.query.perPage || 10;
  let page = req.query.page >= 1 ? req.query.page - 1 : 0;
  let sort = req.query.sort || "_id";
  let reverse = req.query.reverse == "yes" ? -1 : 1;
  let cat = req.query.cat || null
  try{
    objFind = (cat) ? {cat_short_id:cat} : {}
    let data = await SubCategoriesModel.find(objFind)
    .limit(perPage)
    .skip(page * perPage)
    .sort({[sort]:reverse})
    res.json(data);
  }
  catch(err){
    console.log(err)
    res.status(500).json(err)
  }
  
})  

// Returns me subCategory information based on the property of the URL name that the subCategory has
router.get("/single/:url_name", async(req,res) => {
  try{
    let data = await SubCategoriesModel.findOne({url_name:req.params.url_name})
    res.json(data);
  }
  catch(err){
    console.log(err)
    res.status(500).json(err)
  }
})  

//give me the total amount of subCategory in the collection of the db
router.get("/amount", async(req,res) => {
  try{
    let cat = req.query.cat || null
    objFind = (cat) ? {cat_short_id:cat} : {}
    // countDocuments -> return just the amount of documents in the collections
    let data = await SubCategoriesModel.countDocuments(objFind);
    res.json({amount:data});
  }
  catch(err){
    console.log(err)
    res.status(500).json(err)
  }
})

//add new subCategory
router.post("/", authAdmin , async(req,res) => {
  let validBody = validateSubCategories(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try{
    let category = new SubCategoriesModel(req.body);
    category.short_id = await genShortId(); // 0 -999999 that not in use in another SubCategory
    await category.save();

    res.status(201).json(category);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

// Edit subCategory
router.put("/:idEdit", authAdmin , async(req,res) => {
  let validBody = validateSubCategories(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try{
    let idEdit = req.params.idEdit
    let data = await SubCategoriesModel.updateOne({_id:idEdit},req.body)
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

// Delete subCategory
router.delete("/:idDelete", authAdmin , async(req,res) => {
  try{
    let idDelete = req.params.idDelete
    let subcatDel =await SubCategoriesModel.findOne({_id:idDelete})
    let catShortId =subcatDel.short_id;
    await ProductModel.deleteMany({cat_short_id:catShortId})
    let data = await SubCategoriesModel.deleteOne({_id:idDelete});
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})


// generate short id for subCategories
const genShortId = async() => {
  let flag = true; // will become false if not found short_id = rnd
  // check if there no subCategory with rnd = short_id;
  let rnd;
  while(flag){
    rnd = random(0,999999)
    try{
      let data = await SubCategoriesModel.findOne({short_id:rnd})
      if(!data){
        flag = false;
      }
    }
    catch(err){
      console.log(err);
      flag = false;
      return res.status(500).json(err);
    }
  }
  return rnd;
}


module.exports = router;