const express = require("express");
const router = express.Router();

router.get("/", (req,res) => {
  res.json({msg:"Work from index.js 33333"})
})

module.exports = router;