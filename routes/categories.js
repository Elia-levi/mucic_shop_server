const express = require("express");
const {random} = require("lodash")
const { authAdmin } = require("../middlewares/auth");
const { validateCategory, CategoryModel } = require("../models/categoryModel");
const { ProductModel } = require("../models/productModel");
const { SubCategoriesModel } = require("../models/SubCategoriesModel");
const router = express.Router();


// Displays all subcategories with filter option
router.get("/", async(req,res) => {
  let perPage = req.query.perPage || 10;
  let page = req.query.page >= 1 ? req.query.page - 1 : 0;
  let sort = req.query.sort || "_id";
  let reverse = req.query.reverse == "yes" ? -1 : 1;
  try{
    let data = await CategoryModel.find({})
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


// Returns me Category information based on the property of the URL name that the Category has
router.get("/single/:url_name", async(req,res) => {
  try{
    let data = await CategoryModel.findOne({url_name:req.params.url_name})
    res.json(data);
  }
  catch(err){
    console.log(err)
    res.status(500).json(err)
  }
})  

//give me the total amount of category in the collection of the db
router.get("/amount", async(req,res) => {
  try{
    let cat = req.query.cat || null
    objFind = (cat) ? {cat_short_id:cat} : {}
    // countDocuments -> return just the amount of documents in the collections
    let data = await CategoryModel.countDocuments(objFind);
    res.json({amount:data});
  }
  catch(err){
    console.log(err)
    res.status(500).json(err)
  }
})


//add new category
router.post("/", authAdmin , async(req,res) => {
  let validBody = validateCategory(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try{
    let category = new CategoryModel(req.body);
    category.short_id = await genShortId(); // 0 -999999 that not in use in another category
    await category.save();

    res.status(201).json(category);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

//Edit category
router.put("/:idEdit", authAdmin , async(req,res) => {
  let validBody = validateCategory(req.body);
  if (validBody.error) {
    return res.status(400).json(validBody.error.details);
  }
  try{
    let idEdit = req.params.idEdit
    let data = await CategoryModel.updateOne({_id:idEdit},req.body)
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})

//delete category
router.delete("/:idDelete", authAdmin , async(req,res) => {
  try{
    let idDelete = req.params.idDelete
    let catDel =await CategoryModel.findOne({_id:idDelete})
    let catShortId =catDel.short_id;
    let subcatDel =await SubCategoriesModel.find({cat_short_id:catShortId})
    // Returns all short_id of subcategory 
    let shortIdSubCat = subcatDel.map(item => item.short_id)
    // delete all products the have same cat_short_id like SubCategories short_id
    await ProductModel.deleteMany({cat_short_id:{$in:shortIdSubCat}})
    await SubCategoriesModel.deleteMany({cat_short_id:catShortId})
    let data = await CategoryModel.deleteOne({_id:idDelete});
    res.json(data);
  }
  catch(err){
    console.log(err);
    return res.status(500).json(err);
  }
})


// generate short id for categories
const genShortId = async() => {
  let flag = true; // will become false if not found short_id = rnd
  // check if there no category with rnd = short_id;
  let rnd;
  while(flag){
    rnd = random(0,999999)
    try{
      let data = await CategoryModel.findOne({short_id:rnd})
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