var router = require('express').Router();
var bodyParser = require('body-parser');
var nodemailer = require('nodemailer');
var axios = require('axios');
var crypto = require('crypto');
router.use(bodyParser.json());
router.use(bodyParser.urlencoded({ extended: true }));
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var User = require('../models/User');




function encrypt(text,cb) {
   var iv = crypto.randomBytes(16);
   var key = crypto.createCipheriv('aes-128-cbc',process.env.CRYPTOPW, iv);
   var str = key.update(text,'utf8','hex');
   str += key.final('hex');
   cb(str);
 };


router.post('/register', function(req, res) {
  if(req.body.username && req.body.email && req.body.password) {
    User.findOne({email: req.body.email}, function(err, user) {
      if (err) res.status(500).json({message: err.message});
      if(user) {
        res.status(409).json({message: 'User already exists'});
      } else {
          User.findOne({username: req.body.username}, function(err, user) {
            if (err) res.status(500).json({message: err.message});
            if(user) {
              res.status(409).json({message: 'User already exists'});
            } else {
              bcrypt.hash(req.body.password, 10, function(err, hashedPassword) {
                if (err) {
                  res.status(500).json({message: err.message});
                } else {
                  User.create({
                    username: req.body.username,
                    email: req.body.email,
                    password: hashedPassword,
                    role: 'user',
                    //url: req.body.url,
                    url: req.body.url
                  }, function(err, user) {
                    if(err) {
                      res.status(500).json({message: 'Registration failed'});
                    } else {
                      var reftoken = jwt.sign({user_id: user._id}, process.env.SECRET, {expiresIn: '60d'});
                      var token = jwt.sign({user_id: user._id, email: user.email, username: user.username, isVerified: user.isVerified, role: user.role, banned: user.banned, url: user.url}, process.env.SECRET, {expiresIn: '1h'});
                      res.status(200).json({jwt_token: token, refresh_token: reftoken});
                    };
                  });
                };
              });
            };
          });
      };
    });
  } else {res.status(401).json({msg: 'no credentials sent'})};
});

router.post('/login', function(req, res) {
  User.findOne({username: req.body.username}, function(err, user) {
    if (err) res.status(500).json({message: err.message});
    if (!user) {
      res.status(404).json({message: 'This username does not exist.'});
    } else {
      bcrypt.compare(req.body.password, user.password, function(err, isMatch) {
        if (err) res.status(500).json({message: err.message});
        if(!isMatch) {
          res.status(401).json({message:'Wrong Password.'});
        } else {
          var reftoken = jwt.sign({user_id: user._id}, process.env.SECRET, {expiresIn: '60d'});
          var token = jwt.sign({user_id: user._id, email: user.email, username: user.username, isVerified: user.isVerified, role: user.role, banned: user.banned, url: user.url}, process.env.SECRET, {expiresIn: '1h'});
          res.status(200).json({jwt_token: token, refresh_token: reftoken});
        }
      });
    };
  });
});

router.post('/forgot', function(req, res) {
    User.findOne({email: req.body.email}, {password: 0}, function(err, user) {
        if (err) res.status(500).json({message: err.message});
        if(!user) {
          res.status(404).json({message: 'User not found.'});
        } else {
          encrypt(user._id.toString(), function(enc) {
            var transporter = nodemailer.createTransport({
              service: 'Gmail',
              auth: {
                user: process.env.GMAILUSER,
                pass: process.env.GMAILPW
              }
            });
            var mailOptions = {
                from: process.env.GMAILUSER,
                to: user.email,
                subject: 'Password Reset',
                text: 'Hello ' + user.username + '. You request a password reset.\n\n' +
                      'Please follow the link below to create a new password.\n\n' +
                       req.headers.origin + '/#' + '/newPassword/' + enc + '\n\n' +
                      'This link expires in 1 hour.'
            };
            transporter.sendMail(mailOptions, function(error, info){
                if(error){
                    res.status(500).json({message: error.message});
                } else {
                  user.resetPasswordToken = enc;
                  user.resetPasswordExpires = Date.now() + 3600000;
                  user.save(function(err, updated_user) {
                    if (err) res.status(500).json({message: err.message});
                    res.status(200).json({email_sent: true, message: 'Email sent to ' + user.email});
                  });
                }
            });
          }); //encrypt end
        };
    });//User findOne end
});


router.post('/reset', function(req, res) {
  User.findOne({resetPasswordToken: req.body.token}, function(err, user) {
    if(err) res.status(500).json({message: err.message});
    if(!user) {
      res.status(404).json({message: 'Token was already used.' });
    } else {
      if(user.resetPasswordExpires < Date.now()) {
        res.status(410).json({message: 'Token expired.'});
      } else {
        bcrypt.hash(req.body.password, 10, function(err, hashedPassword) {
          if (err) {
            res.status(500).json({message: err.message});
          } else {
            user.password = hashedPassword;
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            user.save(function(err) {
              if (err) res.status(500).json({message: err.message});
              res.status(200).json({success: true});
            });
          };
        });
      };
    };
  });
});

router.post('/verify', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) res.status(401).json({message:'No token provided.'});
  jwt.verify (token, process.env.SECRET, function (err, decoded) {
    if(err) {
      res.status(500).json({message: err.message});
    }
    User.findOne({_id: decoded.user_id}, {password: 0}, function(err, user) {
      if(err) {
        res.status(500).json({message: 'Problem occured while finding the user.'});
      }
      if(!user) {
        res.status(404).json({message: 'No user found'});
      } else {
        encrypt(user._id.toString(), function(enc) {
          var transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
              user: process.env.GMAILUSER,
              pass: process.env.GMAILPW
            }
          });
          var mailOptions = {
              from: process.env.GMAILUSER,
              to: user.email,
              subject: 'Verification',
              text: 'Hello ' + user.username + '\n\n' +
                    'Please follow the link below to verify your email.\n\n' +
                     req.headers.origin + '/#' + '/verify/' + enc + '\n\n' +
                    'This link expires in 1 hour.'
          };
          transporter.sendMail(mailOptions, function(error, info){
              if(error){
                  res.status(500).json({error: error});
              } else {
                user.verifyToken = enc;
                user.verifyTokenExpires = Date.now() + 86400000;
                user.save(function(err, updated_user) {
                  if (err) res.status(500).json({message: err.message});
                  res.status(200).json({message: 'Email sent to ' + user.email});
                });
              }
          }); //sendmail end
        }); //encrypt end
      };
    }); //findOne end
  }); //verify end
});

router.post('/verify/:token', function(req, res) {
  User.findOne({verifyToken: req.params.token}, function(err, user) {
    if(err) res.status(500).json({message: err.message});
    if(!user) {
      res.status(409).json({message: 'User is already verified or the verification token is malformed.'});
    } else {
      if(user.verifyTokenExpires < Date.now()) {
        res.status(410).json({message: 'Verification Token has expired.'});
      } else {
        user.isVerified = true;
        user.verifyToken = undefined;
        user.verifyTokenExpires = undefined;
        user.save(function(err) {
          if (err) res.status(500).json({message: err});
          res.status(200).json({message: 'Your email has been verified.'});
        });
      };
    };
  });
});

router.post('/refreshtoken', function(req, res) {
  var token = req.headers['x-refresh-token'];
  if (!token) res.status(401).json({message:'No token provided'});
  jwt.verify(token, process.env.SECRET, function (err, decoded) {
    if(err) res.status(500).json({message: err.message});
    if(decoded.social) {
      var token = jwt.sign({user: decoded.user_data, isVerified: decoded.isVerified}, process.env.SECRET, {expiresIn: '1h'});
      res.status(200).json({jwt_token: token});
    } else {
      User.findOne({_id: decoded.user_id}, {password: 0}, function(err, user) {
        if(err) res.status(500).json({message: err.message});
        if(!user) {
          res.status(404).json({message: 'No user found'});
        } else {
          var token = jwt.sign({user_id: user._id, email: user.email, username: user.username, isVerified: user.isVerified, role: user.role, banned: user.banned}, process.env.SECRET, {expiresIn: '1h'});
          res.status(200).json({jwt_token: token});
        }
      });
    }
  });
});

router.post('/sociallogin', function(req, res) {
  var access_token = req.body.access_token;
  axios.get('https://graph.facebook.com/me?fields=birthday,gender,first_name,email,picture.type'+'(large)'+'&access_token='+access_token).then(function(response) {
    var reftoken = jwt.sign({user_data: response.data, social:true}, process.env.SECRET, {expiresIn: '60d'});
    var token = jwt.sign({user_data: response.data, isVerified: true, social: true}, process.env.SECRET, {expiresIn: '1h'});
    var user = {username: response.data.first_name, picture: response.data.picture, email: response.data.email, isVerified: true, social: true};
    res.status(200).json({jwt_token: token, refresh_token: reftoken, user: user});
    /*User.findOne({facebook_id: response.data.id}, function(err, user) {
      if(err) res.status(500).json({message: err.message});
      if(!user) {

      } else {
        var reftoken = jwt.sign({user_data: response.data, social:true}, process.env.SECRET, {expiresIn: '60d'});
        var token = jwt.sign({user_data: response.data, isVerified: true, social: true}, process.env.SECRET, {expiresIn: '1h'});
        var user = {username: response.data.first_name, picture: response.data.picture, email: response.data.email, isVerified: true, social: true};
        res.status(200).json({jwt_token: token, refresh_token: reftoken, user: user});
      }
    });*/

  })
  .catch(function(error) {
    res.status(404).json({error:error.response.data.error.message});
  });
});

//TODOCHANGE PASSWORD

module.exports = router;
