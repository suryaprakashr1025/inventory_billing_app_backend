const express = require("express")
const dotenv = require("dotenv").config()
const cors = require("cors")
const bcrypt = require("bcryptjs")
const nodemailer = require("nodemailer")
const jwt = require("jsonwebtoken")
const mongodb = require("mongodb")
const mongoClient = mongodb.MongoClient;
const URL = process.env.DB;
const JWT_SECRET = process.env.JWT_SECRET
const app = express()

// MIDDLEWARE

app.use(cors({
    // origin: "http://localhost:3000",
    origin: "*",
}))

app.use(express.json())


//ADMIN AND LOGIN PAGE

//POST = ADMIN REGISTER PAGE
app.post("/admin/register", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //hasing password
        var salt = await bcrypt.genSalt(10) //secret key
        //console.log(salt)
        var hash = await bcrypt.hash(req.body.password, salt) //hash the password
        //console.log(hash)
        req.body.password = hash;

        //select the collection
        //Do operation
        const checkUsername = await db.collection("admin").find({ username: req.body.username }).toArray()
        console.log(checkUsername.length)

        if (checkUsername.length === 0) {
            const checkEmail = await db.collection("admin").find({ email: req.body.email }).toArray()
            console.log(checkEmail.length)
            if (checkEmail.length === 0) {
                const admin = await db.collection("admin").insertOne(req.body)
                console.log(admin)
                res.status(200).json({ message: "admin created" })
            } else {
                res.json({ message: "username,email and password is already exists" })
            }

        } else {
            res.json({ message: "username,email and password is already exists" })
        }

        //close the connection
        await connection.close()

    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

//POST = ADMIN LOGIN PAGE
app.post("/admin/login", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation
        const admin = await db.collection("admin").findOne({ username: req.body.username })
        console.log(admin)

        if (admin) {
            //create token
            const token = jwt.sign({ _id: admin._id }, JWT_SECRET, { expiresIn: "5m" })
            console.log(token)
            const compare = await bcrypt.compare(req.body.password, admin.password) //req.body.password is automatic hasing === admin.password already hasing
            console.log(compare) //return boolean value
            if (compare) {
                res.status(200).json({ message: "success", token })
            } else {
                res.json({ message: "username and password is incorrect" })
            }
        } else {
            res.json({ message: "username and password is incorrect" })
        }
        //close the connection
        await connection.close()


    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//POST = USER REGISTER PAGE
app.post("/user/register", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation
        const salt = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(req.body.password, salt)
        req.body.password = hash;

        const checkUsername = await db.collection("user").findOne({ username: req.body.username })
        console.log(checkUsername)

        if (!checkUsername) {
            const checkEmail = await db.collection("user").find({ email: req.body.email }).toArray()
            console.log(checkEmail.length)

            if (checkEmail.length === 0) {
                const user = await db.collection("user").insertOne(req.body)
                console.log(user)
                res.status(200).json({ message: "user created" })
            } else {
                res.json({ message: "username,email and password is already exists" })
            }

        } else {
            res.json({ message: "username,email and password is already exists" })
        }

        //close the connection
        await connection.close()



    } catch (error) {
        res.status(401).json({ message: "something went wrong" })
    }
})

//POST = USER LOGIN PAGE
app.post("/user/login", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation
        const loginUser = await db.collection("user").findOne({ username: req.body.username })
        console.log(loginUser)

        if (loginUser) {
            const token = jwt.sign({ _id: loginUser._id }, JWT_SECRET, { expiresIn: "5m" })
            console.log(token)
            const compare = await bcrypt.compare(req.body.password, loginUser.password)
            console.log(compare)
            if (compare) {
                res.json({ message: "success", token })
            } else {
                res.json({ message: "username and password is incorrect" })
            }
        } else {
            res.json({ message: "username and password is incorrect" })
        }

        //close connection
        await connection.close()
    } catch (error) {
        res.status(401).json({ message: "something went wrong" })
    }
})

//PUT = ADMIN PASSWORD CHANGE
app.put("/admin/:username", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        const checkUsername = await db.collection("admin").findOne({ username: req.params.username })
        console.log(checkUsername)
        delete req.body._id
        delete req.body.username
        if (checkUsername) {
            const compare = await bcrypt.compare(req.body.currentPassword, checkUsername.password)
            console.log(compare)
            delete req.body.currentPassword
            if (compare) {
                const salt = await bcrypt.genSalt(10)
                const hash = await bcrypt.hash(req.body.password, salt)
                req.body.password = hash
                const changePassword = await db.collection("admin").updateOne({ username: req.params.username }, { $set: req.body })
                console.log(changePassword)
                res.status(200).json({ message: "password changed successfully" })

                //new password : $2a$10$R93EwsoTAUHjHKnW0RLuAezBADRO8dCN3xtoczaLdOtTb6hKr7AW2

                //current password : $2a$10$HXslJD2SeumtwAbuAJ.DCOTesmiHEBUB3wQIdfnBx8LptQjE2tSyG
            } else {
                res.json({ message: "username and current password is incorrect" })
            }
        } else {
            res.json({ message: "username and current password is incorrect" })
        }

        //connection close
        await connection.close()
    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

//PUT = USER PASSWORD CHANGE
app.put("/user/:username", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        const checkUsername = await db.collection("user").findOne({ username: req.params.username })
        console.log(checkUsername)

        delete req.body._id
        delete req.body.username

        if (checkUsername) {
            const compare = await bcrypt.compare(req.body.currentPassword, checkUsername.password)
            console.log(compare)
            delete req.body.currentPassword

            if (compare) {
                const salt = await bcrypt.genSalt(10)
                const hash = await bcrypt.hash(req.body.password, salt)
                req.body.password = hash
                const changePassword = await db.collection("user").updateOne({ username: req.params.username }, { $set: req.body })
                console.log(changePassword)
                res.status(200).json({ message: "password changed successfully" })
            } else {
                res.json({ message: "username and password is incorrect" })
            }

        } else {
            res.json({ message: "username and password is incorrect" })
        }

        //connection close
        await connection.close()
    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

//POST = ADMIN FORGET PASSWORD
app.post("/admin/forgetpassword", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the datatbase
        const db = connection.db("Inventory_billing_app")
        // console.log("surya")
        //select the collection
        //Do operation
        const adminUsername = await db.collection("admin").findOne({ username: req.body.username })
        console.log(adminUsername)
        delete req.body.username

        if (adminUsername) {
            const adminEmail = req.body.email
            console.log(adminEmail)

            if (adminEmail === adminUsername.email) {
                const salt = await bcrypt.genSalt(2)
                console.log(salt) //salt.length = 29

                const hash = await (await bcrypt.hash(req.body.email, salt)).slice(24, 36)
                console.log(hash) //this hash is sending mail code
                //req.body.email = hash

                //mail code again hash
                const hash1 = await bcrypt.hash(hash, salt)
                console.log(hash1)

                const transporter = nodemailer.createTransport({
                    service: "gmail",
                    auth: {
                        user: process.env.US,
                        pass: process.env.PS
                    }
                })

                const mailOptions = {
                    from: process.env.US,
                    to: req.body.email,
                    subject: "This is forget password mail and do not reply",
                    html: `<h1>This is your current password:</h1>
                                <span><h2>${hash}</h2></span>`
                }

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error)
                    } else {
                        console.log(info);
                        console.log("info:" + info.response)
                    }
                })

                transporter.close()

                delete req.body.email

                const changePassword = await db.collection("admin").updateOne({ username: adminUsername.username }, { $set: { password: hash1 } })
                console.log(changePassword)

                res.json({ message: "mail sent successfully" })
            } else {
                res.json({ message: "username and email is incorrect" })
            }

        } else {
            res.json({ message: "username and email is incorrect" })
        }

        //close the connection
        await connection.close()

    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

//POST = USER FORGET PASSWORD
app.post("/user/forgetpassword", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation
        const userForget = await db.collection("user").findOne({ username: req.body.username })
        console.log(userForget)
        delete req.body.username
        if (userForget) {
            //const userEmail = await db.collection("user").findOne({ email: req.body.email} )
            const userEmail = req.body.email
            console.log(userEmail)
            if (userForget.email === userEmail) {
                const salt = await bcrypt.genSalt(2)
                console.log(salt)
                console.log(salt.length)

                const hash = await (await bcrypt.hash(req.body.email, salt)).slice(25, 35)
                console.log(hash)
                const hash1 = await bcrypt.hash(hash, salt)
                console.log(hash1)

                const transporter = nodemailer.createTransport({
                    service: "gmail",
                    auth: {
                        user: process.env.US,
                        pass: process.env.PS
                    }
                })

                const mailOptions = {
                    from: process.env.US,
                    to: req.body.email,
                    subject: "This is forget password mail and do not reply",
                    html: `<h1>This is your current password:</h1>
                            <h1>${hash}</h1>`
                }

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error)
                    } else {
                        console.log(info)
                        console.log(info.response)
                    }
                })

                transporter.close()
                delete req.body.email;

                const changePassword = await db.collection('user').updateOne({ username: userForget.username }, { $set: { password: hash1 } })
                console.log(changePassword)

                res.status(200).json({ message: "mail sent successfully" })

            } else {
                res.json({ message: "username and email is incorrect" })
            }

        } else {
            res.json({ message: "username and email is incorrect" })
        }

        //connection close
        await connection.close()

    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})



//ADMIN DASHBOARD

//CREATE THE PRODUCTS
app.post("/addproduct", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation
        const products = await db.collection("products").insertOne(req.body)

        //close connection
        await connection.close()

        res.json({ message: "Product Added Successfully" })
    } catch (error) {
        res.status(500).json("something went wrong")
    }
})

//GET THE PRODUCTS
app.get("/getproducts", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation (CRUD)
        const products = await db.collection("products").find().toArray()
        res.json(products)

        //close the connection
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//GET THE ONE PRODUCT
app.get("/getoneproduct/:productid", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //SELECT THE DATABASE
        const db = connection.db("Inventory_billing_app")

        //select the collection
        const getProduct = await db.collection("products").findOne({ _id: mongodb.ObjectId(req.params.productid) })
        await connection.close()
        if (getProduct) {
            res.json(getProduct)
        } else {
            res.status(404).json({ message: "Product not found" })
        }
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//EDIT THE PRODUCTS
app.put("/editproducts/:productid", async (req, res) => {
    try {
        //CONNECT THE DATABASE
        const connection = await mongoClient.connect(URL)

        //SELECT THE DATABASE
        const db = connection.db("Inventory_billing_app")

        //SELECT THE COLLECTION
        //DO OPERATION
        const findProduct = await db.collection("products").findOne({ _id: mongodb.ObjectId(req.params.productid) })
        delete req.body._id;
        if (findProduct) {
            const editProduct = await db.collection("products").updateOne({ _id: mongodb.ObjectId(req.params.productid) }, { $set: req.body })
            res.json({ message: "Product Updated Successfully" })
        } else {
            res.json({ message: "product not found" })
        }

        //CLOSE THE CONNECTION
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//DELETE THE PRODUCTS
app.delete("/deleteproduct/:productid", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation
        const findProduct = await db.collection("products").findOne({ _id: mongodb.ObjectId(req.params.productid) })
        if (findProduct) {
            const deleteProduct = await db.collection("products").deleteOne({ _id: mongodb.ObjectId(req.params.productid) })
            res.json({ message: "product deleted" })
        } else {
            res.status(404).json({ message: "product not found" })
        }

        //close the connection
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})


//GET THE USERS
app.get("/getusers", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //DO operation
        const users = await db.collection("user").find().toArray()
        res.json(users)

        //close the connection
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//SET THE REASON FOR USER [THIS METHOD FOR DELETE THE USER WITH REASON]
app.put("/setreason/:userid", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation

        const setReason = await db.collection("user").updateOne({ _id: mongodb.ObjectId(req.params.userid) }, { $set: { reason: req.body.reason } })
        console.log(setReason)

        res.json({ message: 'updated successfully' })
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//DELETE THE USER
app.delete("/deleteuser/:userid", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //Do operation

        const findEmail = await db.collection('user').findOne({ _id: mongodb.ObjectId(req.params.userid) })
        console.log(findEmail.email)
        console.log(findEmail)
        if (findEmail) {

            const transporter = nodemailer.createTransport({
                service: "gmail",
                auth: {
                    user: process.env.US,
                    pass: process.env.PS
                }
            })

            const mailoptions = {
                from: process.env.US,
                to: `${findEmail.email}`,
                subject: `Inventory Billing Application`,
                html: `<h1>Hi, ${findEmail.username}</h1>
                <h3>${findEmail.reason}.</h3>`
            }

            transporter.sendMail(mailoptions, (err, info) => {
                if (err) {
                    console.log(err)
                } else {
                    console.log(info)
                    // console.log(info.response)
                }
            })

            transporter.close()

            const deleteItem = await db.collection("user").deleteOne({ _id: mongodb.ObjectId(req.params.userid) })
            res.json({ message: "deleted successfully" })

        } else {
            res.json({ message: "user not found" })
        }


        //close the connection
        await connection.close()

    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

// "username": "surya",
// "email": "suryaprakashr1025@gmail.com",
// "phoneno": 9566953853,
// "password":"surya123"

//ASSIGN THE PRODUCT IN USER
app.put("/addproductfield/:productid", async (req, res) => {
    try {
        //CONNECT THE DATABASE
        const connection = await mongoClient.connect(URL)

        //SELECT THE DATABASE
        const db = connection.db("Inventory_billing_app")

        //SELECT THE COLLECTION
        //DO OPERATION
        const productId = await db.collection("user").updateOne({ _id: mongodb.ObjectId(req.params.productid) }, { $set: { productname: req.body.name } })
        const orderProduct = await db.collection("user")
            .aggregate([
                {
                    $match: {
                        _id: mongodb.ObjectId(req.params.productid)
                    }
                },
                {
                    $lookup: {
                        from: "products",
                        localField: `${req.params.productid}`,
                        foreignField: `${req.body.productname}`,
                        as: "orderedList"
                    }
                }
            ])
            .toArray()
        res.json(orderProduct)
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//USER ORDERED THE PRODUCTS
app.post("/orderproduct", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Inventory_billing_app")

        //select the collection
        //do operation
        const orderedList = await db.collection("orderlist").insertOne(req.body)

        res.json(orderedList)

        //close the connection
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

// GET THE ORDERLIST
app.get("/orderlist", async (req, res) => {
    try {
        //CONNECT THE DATABASE
        const connection = await mongoClient.connect(URL)

        //SELECT THE DATABASE
        const db = connection.db("Inventory_billing_app")

        //SELECT THE COLLECTION
        //DO OPERATION 
        const productId = await db.collection("orderlist").find().toArray()
        res.json(productId)
    } catch (error) {
        res.status(500).json({ message: "somthing went wrong" })
    }
})

//DELETE THE ORDERLIST
app.delete("/deleteorder/:orderid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Inventory_billing_app")
        const findorder = await db.collection("orderlist").findOne({ _id: mongodb.ObjectId(req.params.orderid) })
        if (findorder) {
            const deleteorder = await db.collection("orderlist").deleteOne({ _id: mongodb.ObjectId(req.params.orderid) })
            res.json({ message: "Deleted the product" })
        } else {
            res.json({ message: "orderid is not found" })
        }

        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})
//user give the reviews
// app.put("/reviews/:pId", async (req, res) => {
//     try {
//         const connection = await mongoClient.connect(URL)
//         const db = connection.db("Inventory_billing_app")
//         // const reviews = req.body.reviews
//         const putReview = await db.collection("products").updateOne({ _id: mongodb.ObjectId(req.params.pId) }, { $push: { reviews: req.body.reviews } })
//         //console.log(putReview)
//         res.json({ message: "push the review successfull" })
//         await connection.close()
//     } catch (error) {
//         res.status(500).json({ message: "something went wrong" })
//     }
// })

//USER GET THE PRODUCT
app.put("/usergetproduct/:userId", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Inventory_billing_app")
        const getProduct = await db.collection("user").updateOne({ _id: mongodb.ObjectId(req.params.userId) }, { $push: { products: req.body } })
        console.log(getProduct)
        res.json({ message: "product updated successfully", getProduct })
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//USER DELETE THE PRODUCT
app.put("/userdeleteproduct/:userId", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Inventory_billing_app")

        const findProduct = await db.collection("user").findOne({ _id: mongodb.ObjectId(req.params.userId) })

        console.log(findProduct.products)
        const index = findProduct.products.some(prod => {
            return prod.id === req.body.id
        })
        console.log(index)
        // console.log(findProduct.products[index])
        // console.log(findProduct.products[index].id)
        if (index) {
            const deleteProduct = await db.collection("user").updateOne({ _id: mongodb.ObjectId(req.params.userId) }, { $pull: { products: { id: req.body.id } } })
            console.log(deleteProduct)
            res.json({ message: "product deleted successfully" })
        } else {
            res.json({ message: "Product Not found" })
        }

    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//GET ONE USER
app.get("/getoneuser/:userId", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Inventory_billing_app")
        //const getUser = await db.collection("user").findOne({_id:mongodb.ObjectId(req.params.userId)})
        const getUser = await db.collection("user").aggregate([
            {
                $match: {
                    _id: mongodb.ObjectId(req.params.userId)
                }
            },
            {
                $project: {
                    products: "$products"
                }
            }
        ]).toArray()

        res.json(getUser)
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//CHANGE QUANTITY 
app.put("/changequantity/:productid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Inventory_billing_app")

        const find = await db.collection("products").findOne({ _id: mongodb.ObjectId(req.params.productid) })

        // const changeqty = find.countInStock - req.body.qty
        // console.log(changeqty)
        delete req.body._id
        if (find) {
            const sub = await db.collection("products").updateOne({ _id: mongodb.ObjectId(req.params.productid) },
                { $set: { countInStock: req.body.countInStock } })
            console.log(sub)

            res.json({ message: "changed the quantity value(sub)" })
        } else {
            res.json({ message: "product not found" })
        }

        await connection.close()

    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})




app.listen(4000)