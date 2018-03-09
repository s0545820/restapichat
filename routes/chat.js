var router = require('express').Router();
var User = require('../models/User');
var jwt = require('jsonwebtoken');
var http = require('../index');
//var authenticate = require('../auth_middleware');
//router.use(authenticate);

router.get('/online', function(req, res) {
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

router.get('/', function(req, res) {
  /*var io = require('socket.io')(http);
  io.emit("customEmit", 'hey');
  io.on('connection', function(socket) {
    socket.emit("customEmit", 'hey');
    console.log('a user connected');
    socket.on('message', function(data) {
      socket.emit('message', data)
    });
    socket.on('private-message', function(data) {
      socket.to(data.socketid).emit('private-message', data.message);
    });
  });*/
});

module.exports = router;
