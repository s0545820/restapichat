var authenticate = function(req, res, next) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not auth token provided.'});
  jwt.verify (token, process.env.SECRET, function (err, decoded) {
    if(err) {
       res.status(500).json({error: err, message:'Authentication failed.'});
    } else {
      next();
    }
  });
};

module.exports = authenticate;
