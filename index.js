var express = require('express');
var mongoose = require('mongoose');
var morgan = require('morgan');
var bodyParser = require('body-parser');
var bcrypt = require('bcrypt');

var config = require('./config');
var jwt = require('jsonwebtoken');
var User = require('./models/user');

const saltRounds = 10;

var app = express();
mongoose.connect(config.database, { useMongoClient: true });

app.set('superSecret', config.secret);
app.set('port', (process.env.PORT || 5000));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(morgan('dev'));

app.use(express.static(__dirname + '/public'));

// views is directory for all template files
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

app.get('/', function(request, response) {
  response.render('pages/index');
});

app.get('/api/test-hash', function(req, res) {
  var password = req.query.password;
  bcrypt.hash(password, saltRounds, function(err, hash) {
    res.json({hash});
  });
});

app.get('/api/verify-password', function(req, res) {
  var password = req.query.password;
  var hash = req.query.hash;
  bcrypt.compare(password, hash, function(err, compare) {
    res.json({result: compare});
  });
});

app.post('/api/register', function(req, res) {
  const body = req.body;
  const username = body.username;
  const password = body.password;
  const avatar = body.avatar ? body.avatar : '';

  const saveUserFunc = function(hash) {
    const newUser = new User(
      {
        name: username,
        password: hash,
        admin: false,
        avatar: avatar
      }
    );
    newUser.save(function(err) {
      if (err) {
        res.json({
          result: 0,
          message: err
        })
      } else {
        res.json({
          result: 1,
          message: "OK"
        });
      }
    });
  };

  const duplicateUser = User.findOne({'name': username}, function(err, user) {
    if (user) {
      res.json({
        result: 0,
        message: "User already registered"
      });
    } else {
      argon2.hash(password).then(hash => {
        saveUserFunc(hash);
      });
    }
  });

});

app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

// var huy = new User({
//   name: "Nguyen Huy",
//   password: "password",
//   admin: true
// });

// huy.save(function(err) {
//   if (err) {
//     console.log("Error" + err);
//   }
//   else {
//     console.log("Save done");
//   }
// });
