const axios = require("axios");
const jwt = require("jsonwebtoken");
const { config } = require("../config/secret");


// authentication if have token or not
exports.auth = (req,res,next) => {
  let token = req.header("x-api-key");
  if(!token){
    return res.status(401).json({err:"You must send token in header to this endpoint"})
  }
  try{
    let decodeToken = jwt.verify(token, config.tokenSecret);
    req.tokenData = decodeToken;
    next();
  }
  catch(err){
    return res.status(401).json({err:"Token invalid (if you hacker) or expired"});
  }
}

// authentication if have token of admin or not
exports.authAdmin = (req,res,next) => {
  let token = req.header("x-api-key");
  if(!token){
    return res.status(401).json({err:"You must send token in header to this endpoint"})
  }
  try{
    let decodeToken = jwt.verify(token, config.tokenSecret);
    // check if user role is admin
    if(decodeToken.role == "admin"){
      req.tokenData = decodeToken;
      next();
    }
    else{
      return res.status(401).json({err:"You must be admin in this endpoint"})
    }  
  }
  catch(err){
    return res.status(401).json({err:"Token invalid (if you hacker) or expired"});
  }
}

// authentication of paypal
exports.payPalAuth = async (_tokenId, _orderId, _ifRealPay = true) => {
  
  let url = !_ifRealPay ? "https://api-m.sandbox.paypal.com/v2/checkout/orders/" + _orderId : "https://api-m.paypal.com/v2/checkout/orders/" + _orderId;
  try {
    let resp = await axios({
      method: "GET",
      url: url,
      headers: {
        'Authorization': "Bearer " + _tokenId,
        'content-type': "application/json"
      }
    });
    return resp.data;
  }
  catch (err) {
    console.log(err.response)
    return (err.response)
  }

}