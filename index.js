require('dotenv').config()
var express = require('express');
var app = express();
var fs = require('fs');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var User = require('./models/User');
var http = module.exports = require('http').Server(app);
var port = process.env.PORT || 3000;
var io = require('socket.io')(http);



//setting up mongoose
var mongourl = 'mongodb://' + process.env.MONGOUSER + ':' + process.env.MONGOPW + '@ds111319.mlab.com:11319/chat';
mongoose.connect(mongourl);
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

//body-parser middleware

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//CORS Middleware

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", ["x-access-token", "x-refresh-token"]);
  res.header("Access-Control-Allow-Methods", "*");
  next();
});

//setting up the routes

var index = require('./routes/index');
var users = require('./routes/users');
var chat = require('./routes/chat');
app.use('/api', index);
app.use('/api/users', users);
app.use('/chat', chat);

var log = function(msg) {
  var date = new Date();
  var from = msg.from;
  var message = msg.msg;
  var all = date + ' : "' + from + ': ' + message + '"';
  fs.writeFile("chat.txt", all, function(err) {
      if(err) {
          return console.log(err);
      }
  });
};



              /***CHAT***/
var connected_users = [];
io.on('connection', function(socket){
  console.log(socket.id + ' connected');
  socket.on('disconnect', function() {
    for(let i = 0; i < connected_users.length; i++) {
      if(connected_users[i].socketid === socket.id) {
        connected_users.splice(i,1);
        console.log(connected_users);
      }
    };
    socket.broadcast.emit('disconnected', socket.id);
    console.log(socket.id + ' disconnected');
  });
  socket.on('chat message', function(msg){
    io.emit('recieveMessage', msg);
    log(msg);
  });
  socket.on('private-message', function(data) {
    socket.to(data.socketid).emit('recieveMessage', data.msg);
    socket.emit('recieveMessage', data.msg);
    log(data.msg);
  });
  socket.on('joined', function(user) {
    var set = true;
    var usr = {
      socketid: socket.id,
      username: user.username,
      user_id: user.user_id
    };
    if(connected_users.length > 0) {
      for(let item of connected_users) {
        if(item.socketid == socket.id) {
          set = false;
          break;
        }
      }
      if(set) {
        socket.emit('loadUsers', connected_users);
        connected_users.push(usr);
        socket.broadcast.emit('added', usr);
      }
    } else {
      connected_users.push(usr);
    }
    console.log(connected_users);
  });
});









http.listen(port);
