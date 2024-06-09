import express from 'express'
import mongoose from 'mongoose'
import 'dotenv/config'
import bcrypt from 'bcrypt'
import { nanoid } from 'nanoid'
import jwt from 'jsonwebtoken'
import cors from 'cors'

import User from './server/Schema/User.js'

import aws from "aws-sdk"

const server = express()
let PORT = 4000

let passwordRegex = /^(?=.*\d).{3,20}$/; // regex for password

server.use(express.json())
server.use(cors())

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true
})

//s3 bucket setup
const s33 = new aws.S3({
    region: 'us-east-2',
    acccessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY 
})

const formatDatatoSend = (user) => {

    const access_token = jwt.sign({id : user._id}, process.env.SECRET_ACCESS_KEY)

    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname,
        uid: user.personal_info.uid
    }
}

server.post("/signup", (req, res) => {
    let {fullname, uid, password} = req.body

    if(fullname.length < 3){
        return res.status(403).json({"error": "Full name must be longer than 2 characters"})
    }

    if(!passwordRegex.test(password)){
        return res.status(403).json({"error": "Password should be from 2-20 characters long and including a number"})
    }

    bcrypt.hash(password, 10, async (err, hashed_password) => {
        
        let username = uid
        if (!username) {
            return res.status(500).json({"error": "Unable to generate a unique username"});
        }
        
        let user = new User({
            personal_info: {fullname, uid, password: hashed_password, username}
        });
        
        user.save().then((u) => {
            return res.status(200).json(formatDatatoSend(u));
        })
        .catch(err => {
            console.error("Error saving user:", err);
            return res.status(500).json({ "error": err.message });
        });
        
    } )

})

server.post("/signin", (req, res) => {
    let {fullname, password} = req.body

    User.findOne({"personal_info.uid": uid})
    .then((user) => {
        if(!user){
            throw 'error'
        }

        bcrypt.compare(password, user.personal_info.password, (err, result) => {
            if (err) {
                return res.status(403).json({"error": "error occured while logging in, please try again"})
            }
            if(!result){
                return res.status(403).json({"error": "incorrect password, please try again"})
            } else {
                return res.status(200).json(formatDatatoSend(user))
            }
        })

    })
    .catch(err => {
        console.log(err)
        return res.status(403).json({"error": err.message})
    })
})

server.listen(PORT, () => {
    console.log('listening on port ' + PORT)
})