// SERVER-SIDE JAVASCRIPT

// require express framework and additional modules
var express = require('express'),
	app = express(),
	ejs = require('ejs'),
	bodyParser = require('body-parser'),
	mongoose = require('mongoose'),
	User = require('./models/user'),
	session = require('express-session');

// connect to mongodb
mongoose.connect('mongodb://localhost/test');

// set view engine for server-side templating
app.set('view engine', 'ejs');

// middleware
app.use(bodyParser.urlencoded({extended: true}));

// set session options (also middleware)
app.use(session({
	saveUninitialized: true,
	resave: true,
	secret: 'SuperSecretCookie',
	cookie: { maxAge: 60000 }
}));

// middleware to manage sessions
app.use('/', function (req, res, next) {
	// saves userId in session for logged-in user
	req.login = function (user) {
		req.session.userId = user.id;
	};

	// finds user currently logged in based on session.userId
	req.currentUser = function (callback) {
		User.findOne({_id: req.session.userId}, function (err, user) {
			req.user = user;
			callback(null, user);
		});
	};

	// destroy session.userId to log out user
	req.logout = function () {
		req.session.userId = null;
		req.user = null;
	};

	next();
});

// signup route with placeholder response
app.get('/signup', function(req, res) {
	res.send('coming soon');
});

// user submits the signup form
app.post('/users', function (req, res) {
	// grab user data from params (req.body)
	var newUser = req.body.user;

	// create new user with secure password
	User.createSecure(newUser.email, newUser.password, function (err, user) {
		res.send(user);
	});
});

// user submits the login form
app.post('/login', function (req, res) {
	// grab user data from params (req.body)
	var userData = req.body.user;

	// call authenticate function to check if pw is correct
	User.authenticate(userData.email, userData.password, function (err, user) {
		// saves user id to session
		req.login(user);

		// redirect to user profile
		res.redirect('/profile');
	});
});

// user profile page
app.get('/profile', function (req, res) {
	// finds user currently logged in
	req.currentUser(function (err, user) {
		res.send('Welcome ' + user.email);
	});
});

// login route (renders login view)
app.get('/login', function (req, res) {
	res.render('login');
});












// listen on port 3000
app.listen(3000, function() {
	console.log('server started on localhost:3000');
});