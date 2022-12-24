const express=require('express');
const router=express.Router();
const Contacts=require('../models/Contacts');
const User=require('../models/User');
router.use(express.json());
const cors=require('cors');
router.use(cors());
const {validate}=require('../middleware/middleware');
const bodyParser=require('body-parser');

router.use(bodyParser.urlencoded({extended:false}));
router.use(bodyParser.json());

// CREATE
router.post('/create',validate,cors(),async(req,res)=>{
    try{
        let users=await Contacts.find({userId:req.user});
        if(users.length>0){
            users=await Contacts.find({userId:req.user}).updateOne(
                {},
                {
                    $push:{
                        contact:req.body
                    }
                }
            );
        }else{
            users=await Contacts.create({
                contact:req.body,
                userId:req.user
            });
        }

        res.status(200).json({
            status:"success",
            result:users
        });
    }catch(e){
        res.status(400).json({
            status:"failed",
            error:e.message
        });
    }
});

// GET ONE
router.get('/user',validate,async(req,res)=>{
    try{
        const user=await User.findOne({_id:req.user});
        res.status(200).json({
            user
        });
    }catch(e){
        res.status(400).json({
            error:e.message
        });
    }
});

// GET ALL
router.get('/alluser',validate,async(req,res)=>{
    try{
        const users=await Contacts.find({userId:req.user});
        res.status(200).json({
            users
        });
    }catch(e){
        res.status(400).json({
            error:e.message
        });
    }
});

// DELETE
router.delete('/delete/:id',validate,async(req,res)=>{
    try{
        let user=await Contacts.updateOne({userId:req.user},{$pull:{contact:{_id:req.params.id}}});
        res.status(200).json({
            status:"success",
            user
        })
    }catch(e){
        res.status(400).json({
            status:"failed",
            error:e.message
        })
    }
});

module.exports=router;