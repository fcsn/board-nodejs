var mongoose = require("mongoose");
var bcrypt = require("bcrypt-nodejs"); // 1

// schema ...
// virtuals ...

// password validation
userSchema.path("password").validate(function(v) {
 var user = this;

 // create user ...

 // update user
 if(!user.isNew){
  if(!user.currentPassword){
   user.invalidate("currentPassword", "Current Password is required!");
  }
  if(user.currentPassword && !bcrypt.compareSync(user.currentPassword, user.originalPassword)){ // 2
   user.invalidate("currentPassword", "Current Password is invalid!");
  }
  if(user.newPassword !== user.passwordConfirmation) {
   user.invalidate("passwordConfirmation", "Password Confirmation does not matched!");
  }
 }
});

// hash password // 3
userSchema.pre("save", function (next){
 var user = this;
 if(!user.isModified("password")){ // 3-1
  return next();
 } else {
  user.password = bcrypt.hashSync(user.password); // 3-2
  return next();
 }
});

// model methods // 4
userSchema.methods.authenticate = function (password) {
 var user = this;
 return bcrypt.compareSync(password,user.password);
};


// model & export
var User = mongoose.model("user",userSchema);
module.exports = User;
