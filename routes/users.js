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
    User.find({}, function(err, users) {
      if (err)
          res.status(500).json({message: err.message});
      if (!users)
          res.status(401).json({message: 'No users.'});
      res.status(200).json({users: users});
    });
  });
});
router.post('/ban', function(req,res) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not authenticated. Please log in.'});
  jwt.verify(token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    User.findOne({_id: decoded.user_id}, {password: 0}, function(err, user) {
      if (err)
          res.status(500).json({message: err.message});
      if (!user) {
        res.status(404).json({message: 'No User found.'});
      } else {
        if(user.role === 'admin') {
          User.findOne({_id: req.body.userid}, {password: 0}, function(err, user_to_ban) {
            if (err)
                res.status(500).json({message: err.message});
            if (!user_to_ban) {
              res.status(404).json({message: 'No User found.'});
            } else {
              user_to_ban.banned = true;
              user_to_ban.save(function(err) {
                if (err) res.status(500).json({message: err.message});
                res.status(200).json({success: true, message: 'User was successfully banned.'});
              });
            }
          });
        } else {
          res.status(501).json({message: 'You are not allowed to ban users.'});
        }
      }
    });
  });
});
router.post('/unban', function(req,res) {

});
router.get('/banned', function(req,res) {
  var banned_users = [];
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'Not authenticated. Please log in.'});
  jwt.verify(token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    if(decoded.role == 'admin') {
      User.find({}, function(err, users) {
        if (err)
            res.status(500).json({message: err.message});
        if (!users) {
            res.status(401).json({message: 'No banned users.'});
        } else {
          for(user in users) {
            if(user.banned) {
              banned_users.push(user);
            }
          }
          res.status(200).json({users: banned_users});
        }
      });
    }
  });
});

module.exports = router;
