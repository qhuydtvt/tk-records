var express = require('express');
var mongoose = require('mongoose');
var morgan = require('morgan');
var bodyParser = require('body-parser');
var bcrypt = require('bcrypt');
var cors = require('cors');

var config = require('./config');
var jwt = require('jsonwebtoken');
var User = require('./models/user');

const saltRounds = 10;

var app = express();
app.use(cors({credentials: true, origin: true}));

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

const apiRoutes = express.Router();

app.get('/', function(request, response) {
  response.render('pages/index');
});

apiRoutes.post('/login', function(req, res) {
  const body = req.body;
  const username = body.username;
  const password = body.password;
  User.findOne({'name': username}, function(err, user) {
    if (err) {
      res.json({ result: 0, message: "Something wrong", error: err });
    }

    if (!user) {
      res.json( {result: 0, message:'User not found'} );
    } else {
      bcrypt.compare(password, user.password, function(err, compare) {
        if (compare) {
            const token = jwt.sign(user, app.get('superSecret'), { expiresIn: '8d' } );
            res.json({ result: 1, message: "Login ok", token: token });
            // TODO: Log user in here
        } else {
          res.json({result: 0, message: "Password doesn't match"});
        }
      });
    }
  });
});

apiRoutes.post('/users', function(req, res) {
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
      bcrypt.hash(password, saltRounds, function(err, hash) {
        saveUserFunc(hash);
      });
    }
  });
});

apiRoutes.use(function(req, res, next){
  var token = req.body.token || req.query.token || req.headers['x-access-token'];
  if (token) {
    jwt.verify(token, app.get('superSecret'), function(err, decoded){
      if(err) {
        return res.json({ result:0, message:"Cannot decode given token" });
      } else {
        req.user = decoded._doc;
        next();
      }
    });
  } else {
    res.json({ result: 0, message: "Token not provided" });
  }
});

apiRoutes.get('/login', function(req, res) {
  const {__v, _id, admin, ...user} = res.user;
  res.json(user);
});

apiRoutes.get('/test-hash', function(req, res) {
  var password = req.query.password;
  bcrypt.hash(password, saltRounds, function(err, hash) {
    res.json({hash: hash});
  });
});

apiRoutes.get('/api/verify-password', function(req, res) {
  var password = req.query.password;
  var hash = req.query.hash;
  bcrypt.compare(password, hash, function(err, compare) {
    res.json({result: compare});
  });
});


app.use('/api', apiRoutes);

app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});
