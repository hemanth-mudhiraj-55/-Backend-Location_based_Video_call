const express =require('express')
const app = express()
const mongoClient =require('mongodb').MongoClient

const url ='mongodb://localhost:27017'

mongoClient.connect(url,(err,db)=>{
    if(err){
        console.log('Error while Connecting mongo')
    }
    else{
        const mydb=db.db('myWindow')
        const collection = mydb.collection('registration')

        // post request 

        app.post('/Confirm',(req,res)=>{

            const query ={
                email : newUser.email,
                uid: newUser.uid,
                mobile: newUser.mobile
            }

            collection.findOne(query , (err, result)=>{

                if(result==null){
                   
                }
                else{
                    res.status(400).send()
                }
            })
        })

        app.post('/Submit',(req,res)=>{
            const newUser ={
                uid : req.body.uid,
                name : req.body.name,
                email :req.body.email,
                mobile : req.body.mobile,
                password : req.body.password,
                gender : req.body.gender,
                profile_pic : req.body.profile_pic

            }
        })
    }
})

app.use(express.json()) // post request is post type json
app.listen(3000,()=>{
    console.log('Listening on port: 3000')
})