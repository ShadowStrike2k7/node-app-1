require("dotenv").config()
bcrypt = require("bcrypt")
const sanitizeHTML = require("sanitize-html")
const cookieparser = require("cookie-parser")
const jwt = require("jsonwebtoken")
const express = require("express")
const db = require("better-sqlite3")("our-app.db")
const marked = require("marked")
db.pragma("journal_mode = WAL")

// ------ Database Setup ------
const createTables = db.transaction(() =>{

    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )`).run()
    
    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorID INTEGER,
        FOREIGN KEY (authorID) REFERENCES users (id)
        )`).run()
})

createTables()

//

const app = express()

app.set("view engine","ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(cookieparser())

app.use(function (req,res,next){
    res.locals.filterUserHtml = function(content){
        return sanitizeHTML(marked.parse(content),{
            allowedTags: ["p","br","ul","ol","li","strong","bold","i","em","h1","h2","h3","h4"],
            allowedAttributes: {}
        })
    }
    res.locals.err = []

    try {
        const decoded = jwt.verify(req.cookies.Oursimpleapp, process.env.JWTSECRET)
        req.user = decoded
    } catch (error) {
        req.user = false
    }
    res.locals.user = req.user
    next()
})

function checkLogin(req,res,next) {
    if(req.user){
        return next()
    }
    res.redirect("/")
}


app.get("/",(req,res) => {
    if(req.user){
        const postsSt = db.prepare("SELECT * FROM posts WHERE authorID = ? ORDER BY createdDate DESC")
        const posts = postsSt.all(req.user.userid)
        return res.render("dashboard",{posts})
    }
    res.render("home")
})

app.get("/login", (req,res) =>{
    res.render("login")
})

app.get("/logout",(req,res) => {
    res.clearCookie("Oursimpleapp")
    res.redirect("/")
})

app.get("/create-post",checkLogin,(req,res) => {
    res.render("create-post")
})

app.get("/edit-post/:id",checkLogin,(req,res) =>{
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    if(!post) return res.redirect("/")

    if(post.authorID !== req.user.userid) return res.redirect("/")
    
    res.render("edit-post", { post })

})

app.get("/post/:id",(req,res) => {
    const st = db.prepare("SELECT posts.*,users.username FROM posts INNER JOIN users ON posts.authorID = users.id WHERE posts.id = ?")
    const post = st.get(req.params.id)

    if(!post){
        return res.redirect("/")
    }
    const isAuthor = post.authorID === req.user.userid

    res.render("single-post", { post,isAuthor })
})

app.post("/login",checkLogin, (req,res) => {
    let err =[]
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    if (req.body.username.trim() == "" || req.body.password === "" ) err = ["Invalid username/password"]
    if(err.length){
        return res.render("login",{err})
    }
    const userInQ = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userIQ =userInQ.get(req.body.username)

    if(!userIQ){
        err = ["Invalid username/password"]
        return res.render("login",{err})
    }

    const match = bcrypt.compareSync(req.body.password,userIQ.password)
    if(!match){
        err = ["Invalid username/password"]
        return res.render("login",{err})
    }

    const tokenVal = jwt.sign({exp: Math.floor(Date.now()/1000) + 60 * 60 * 24 ,userid: userIQ.id, username: userIQ.username},process.env.JWTSECRET)
    res.cookie("Oursimpleapp",tokenVal,{
        httpOnly:true,
        secure:true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 48
    })
    res.redirect("/")
})

app.post("/edit-post/:id",checkLogin,(req,res) => {
    console.log("editing now")
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    if(!post) return res.redirect("/")

    if(post.authorID !== req.user.userid) return res.redirect("/")
    
    const errs = postValidationCheck(req)

    if(errs.length) return res.render("edit-post", {errs})
    
    const updateSt = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")
    updateSt.run(req.body.title,req.body.body,req.params.id)

    res.redirect(`/post/${req.params.id}`)
})

app.post("/delete-post/:id",checkLogin,(req,res) => {
    console.log("deleting post")
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    if(!post) return res.redirect("/")

    if(post.authorID !== req.user.userid) return res.redirect("/")

    const delSt = db.prepare("DELETE FROM posts WHERE id = ? ")
    delSt.run(req.params.id)
})

app.post("/register",(req,res) =>{
    const err =[]
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()
    if(!req.body.username) err.push("Must Enter a valid username!")
    if(req.body.username && req.body.username.length < 3) err.push("Username must be atleast 3 characters long")
    if(req.body.username && req.body.username.length > 12) err.push("Username must not be more than 12 characters long")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) err.push("Username can only contain chars and nums")

    const usernameSt = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const usernameCheck = usernameSt.get(req.body.username)

    if (usernameCheck) err.push("The username is already taken!")

    if(!req.body.password) err.push("Must Enter a valid password!")
    if(req.body.password && req.body.password.length < 4) err.push("username must be atleast 4 characters long")
    if(req.body.password && req.body.password.length > 12) err.push("username must not be more than 12 characters long")
    // if(req.body.password && !req.body.password.match(/^[a-zA-Z0-9]+$/)) err.push("username can only contain chars and nums")

    if (err.length) {
        return res.render("home",{err})
    } 
    // saving user into db
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?,?)")
    const result = ourStatement.run(req.body.username,req.body.password)

    const lookUpStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const getUser = lookUpStatement.get(result.lastInsertRowid)

    //login user by giving them a cookie
    const tokenVal = jwt.sign({exp: Math.floor(Date.now()/1000) + 60 * 60 * 24 ,userid: getUser.id, username: getUser.username},process.env.JWTSECRET)
    res.cookie("Oursimpleapp",tokenVal,{
        httpOnly:true,
        secure:true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 48
    })
    res.redirect("/")
})

function postValidationCheck(req){
    const err = []

    if(typeof req.body.title !== "string") req.body.title = ""
    if(typeof req.body.body !== "string") req.body.body = ""

    req.body.title = sanitizeHTML(req.body.title.trim(),{allowedTags:[],allowedAttributes:{}})
    req.body.body = sanitizeHTML(req.body.body.trim(),{allowedTags:[],allowedAttributes:{}})

    if(!req.body.title) err.push("Title cant be empty")
    if(!req.body.body) err.push("Body cant be empty")

    return err
}

app.post("/create-post", checkLogin, (req, res) => {
 const err = postValidationCheck(req)

  if (err.length) {
    return res.render("create-post", { err })
  }

  // save into database
  const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)")
  const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString())

  const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
  const realPost = getPostStatement.get(result.lastInsertRowid)

  res.redirect(`/post/${realPost.id}`)
})

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log("Server running on port " + port);
});
