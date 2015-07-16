var mongoose = require('mongoose'),
	Schema = mongoose.Schema,
	bcrypt = require('bcrypt'),
	salt = bcrypt.genSaltSync(10);

// define the user Schema
var UserSchema = new Schema({
	email: String,
	passwordDigest: String // indicates that we are storing a hashed, salted version of the password, not the password itself
});

// define user authentication methods
// create a new user with hashed and salted password
UserSchema.statics.createSecure = function(email, password, callback) {
	// 'this' references our schema initially
	// store it in var 'that' bc 'this' changes context in nested callbacks
	var that = this;

	// hash pw entered by user at sign up
	bcrypt.genSalt(function (err, salt) {
		bcrypt.hash(password, salt, function (err, hash) {
			console.log(hash);

			// create the new user (save to db) w/ hashed pw
			that.create({
				email: email,
				passwordDigest: hash
			}, callback);
		});
	});
};
// authenticate user upon login
UserSchema.statics.authenticate = function (email, password, callback) {
	// find user by email entered at login
	this.findOne({email: email}, function (err, user) {
		console.log(user);

		// throw error if can't find user
		if (user === null) {
			throw new Error('Can\'t find user with email ' + email);
		
		// if found user, check password
		} else if (user.checkPassword(password)) {
			callback(null, user);
		}
	});
};

// compare password user enters with hashed pw (passwordDigest)
UserSchema.methods.checkPassword = function (password) {
	// run hashing algorithm (with salt) on pw entered to compare with passwordDigest
	return bcrypt.compareSync(password, this.passwordDigest);
};


// define the user model
var User = mongoose.model('User', UserSchema);

// export the user model
module.exports = User;