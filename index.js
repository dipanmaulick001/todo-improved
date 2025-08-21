const express = require("express");
const z = require("zod");
const jwt = require("jsonwebtoken");
const JWT_SECRET = "asdddddd"
const bcrypt = require("bcrypt");

const { UserModel , TodoModel } = require("./db");
const mongoose = require("mongoose");


async function startServer() {
    try {
        await mongoose.connect("");
        console.log("Connected to MongoDB");

        app.listen(3003,"0.0.0.0", () => {
            console.log("Listening on port 3003");
        });
    } catch (err) {
        console.error("MongoDB connection error:", err);
    }
}

startServer();

const app = express();
app.use(express.json());

app.post('/signup' , async function(req , res){

    //zod se input validation first , then actual input lega
    const requiredBody = z.object({
        email : z.email(),
        password : z.string()
            .min(5)
            .max(12)
            .regex(
                /^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?":{}|<>]).*$/,
                "Password must have atleast one lowercase character,one uppercase character and one special character"
            ),
        name : z.string()
    })

    const parsedData = requiredBody.safeParse(req.body);

    if(!parsedData.success){
            res.json({
            message : "Incorrect format of input",
            error : parsedData.error
            })
            return
    }

    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;

    let errorThrown = false;

    try {
        const hashedPass = await bcrypt.hash(password , 10);
        await UserModel.create({
            name : name,
            password : hashedPass, 
            email : email
        })
        
    } catch (error) {
        console.log("signup error: ", error)
        errorThrown = true;
        
    }

    if(!errorThrown){
        res.json({
            msg : "You are signed up"
        })


    }


})

app.post("/login" , async function( req , res){
    const email = req.body.email ;
    const password = req.body.password;

    

    const response = await UserModel.findOne({
        email : email
    })
    if (!response){
        res.status(403).json({
            message : "Incorrect email"
        })
    }

    const passwordMatch = await bcrypt.compare(password , response.password);
    if (passwordMatch){
        const token = jwt.sign({
            id : response._id.toString()
        },JWT_SECRET)
        res.json({
            token : token
        })

    }else{
        res.status(403).json({
            message : "Incorrect credentials"
        })
    }
    
})

function auth(req , res , next){
    const token = req.headers.token ;
    const decodedData = jwt.verify( token , JWT_SECRET);
    if (decodedData){
        req.userId = decodedData.id;
        next()
    }else{
        res.status(403).json({
            message : 'Wrong creds'
        })
    }

}

app.post("/todo" , auth , async function( req , res){
    const userId = req.userId;
    const title = req.body.title 

    await TodoModel.create({
        title : title,
        userId : userId
    })
    res.json({
        message : "Todo created"
    })

})

app.get("/todos" , auth,  async function ( req , res){
    const userId = req.userId;
    const todos = await TodoModel.find({
        userId : userId
    })
    res.json({
        todos
    })

})


