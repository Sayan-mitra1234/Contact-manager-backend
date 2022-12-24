const mongoose=require('mongoose');

const UserSchema=new mongoose.Schema({
    email:{
        type:String,
        required:[true,"email is required"]
    },
    password:{
        type: String,
        required:[true,"password is required"]
    }
});

const User=new mongoose.model("user",UserSchema);
module.exports=User;