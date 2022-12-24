const express=require('express');
const app=express();
const dotenv=require('dotenv');
const cors=require('cors');
const connectDB=require('./connectDB/db');
const userRouter=require('./routes/user');
const contactsRouter=require('./routes/contacts');

dotenv.config();
app.use(cors());
app.use(express.json());


// routes
app.use('/',userRouter);
app.use('/',contactsRouter);
app.get('*',(req,res)=>{
    res.status(404).send("404, PAGE NOT FOUND");
});


// server config
app.listen(process.env.PORT,async()=>{
    try{
        await connectDB();
        console.log("Server is Running at Port",process.env.PORT);
    }catch(e){
        console.log(e);
    }
});