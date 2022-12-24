const mongoose=require('mongoose');

const ContactSchema=new mongoose.Schema({
    contact:[{
        Name:String,
        Designation:String,
        Company:String,
        Industry:String,
        Email:String,
        PhoneNumber:String,
        Country:String
    }],
    userId:{type:mongoose.Schema.Types.ObjectId,ref:"User"}
});

const ContactsModel=new mongoose.model("contacts",ContactSchema);
module.exports=ContactsModel;