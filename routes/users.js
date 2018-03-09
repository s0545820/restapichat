var router = require('express').Router();
var User = require('../models/User');
var jwt = require('jsonwebtoken');
//var authenticate = require('../auth_middleware');
//router.use(authenticate);

/*router.get('/', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not authenticated. Please log in.'});
  jwt.verify (token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    User.find({}, {password: 0}, function(err, users) {
      if(err) res.status(500).json({message: 'Problem occured while finding users.'});
      if(!users) {
        res.status(401).json({message: 'No users found'});
      } else {
        res.status(200).json({users: users});
      }
    })
  });
});*/

router.get('/:user_id', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not authenticated. Please log in.'});
  jwt.verify (token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    User.findById(req.params.user_id, {password: 0}, function(err, user) {
        if (err)
            res.status(500).json({message: err.message});
        if (!user)
            res.status(401).json({message: 'User not found.'});
        res.status(200).json(user);
    });
  });
});

router.put('/', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not authenticated. Please log in.'});
  jwt.verify (token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    User.findByIdAndUpdate({_id: decoded.user_id}, req.body, function(err, user) {
      if (err)
          res.status(500).json({message: err.message});
      if (!user)
          res.status(401).json({message: 'User not found.'});
        res.json({username: user.username, email: user.email});
    });
  });
});

router.delete('/', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not authenticated. Please log in.'});
  jwt.verify(token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    User.findByIdAndRemove(req.body.user_id, {password: 0}, function(err, user) {
        if (err)
            res.status(500).json({message: err.message});
        if (!user)
            res.status(401).json({message: 'User not found.'});
        res.status(200).json({message: 'User deleted!'});
    });
  });
});

router.put('/status', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not authenticated. Please log in.'});
  jwt.verify(token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    User.findByIdAndUpdate({_id: decoded.user_id}, req.body, function(err, user) {
      if (err) res.status(500).json({message: err.message});
      if (!user) res.status(401).json({message: 'User not found.'});
      res.status(200).json({message: 'User is now online'});
    });
  });
});

router.get('/', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not authenticated. Please log in.'});
  jwt.verify(token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    User.find({status: 1}, function(err, users) {
      if (err)
          res.status(500).json({message: err.message});
      if (!users)
          res.status(401).json({message: 'No online users.'});
      res.status(200).json({users: users});
    });
  });
});

module.exports = router;
