const indexR = require("./index");
const usersR = require("./users");
const categoriesR = require("./categories");
const productsR = require("./products");
const favsR = require("./favProducts");
const ordersR = require("./orders");
const SubCategoriesR = require("./SubCategories");

exports.routesInit = (app) => {
  app.use("/",indexR);
  app.use("/users", usersR);
  app.use("/categories",categoriesR);
  app.use("/products",productsR);
  app.use("/favs",favsR);
  app.use("/orders",ordersR);
  app.use("/SubCategories",SubCategoriesR);


  app.use((req,res) => {
    res.status(404).json({msg_error:"Url not found , 404!"})
  })
}


exports.corsAccessControl = (app) => {
  app.all('*', function (req, res, next) {
    if (!req.get('Origin')) return next();

    res.set('Access-Control-Allow-Origin', '*');
    res.header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, PATCH");
    res.set('Access-Control-Allow-Headers', 'X-Requested-With,Content-Type,auth-token,x-api-key');
    next();
  });
}