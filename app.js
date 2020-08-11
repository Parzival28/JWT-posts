const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const app = express();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require('dotenv')
dotenv.config();


mongoose.connect(
  "mongodb://localhost:27017/JWT",
  {
    useNewUrlParser: true,
  },
  () => console.log("Connected to db")
);
app.use(express.json());

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  date: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("UserData", userSchema);

app.post("/api/user/register", async (req, res) => {
  const emailExist = await User.findOne({ email: req.body.email });
  if (!emailExist) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    const user = new User({
      email: req.body.email,
      password: hashedPassword,
    });

    const savedUser = user.save();
    res.send("Saved");
  } else {
    console.log("exist");
    return res.status(400).send("Email Already exist");
  }
});

app.post("/api/user/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send("Email is not found");
  const validPass = await bcrypt.compare(req.body.password, user.password);
  if (!validPass) {
    return res.status(400).send("invalid password");
  }

  // token
  const token = jwt.sign({_id: user._id}, process.env.SECRET_TOKEN)
  res.header('auth-token', token).send("Logged in");
});


const verify = function auth (req, res, next) {
    const token = req.header('auth-token');
    if (!token)   return res.status(401).send("Access denied")
    try {
        const verified = jwt.verify(token, process.env.SECRET_TOKEN);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid token")
    }
}

app.get('/api/posts', verify,(req, res) => {
    // res.json({
    //     posts: {
    //         title: "First Post",
    //         description: "random data you shouldnt access"
    //     }
    // });
    res.send(req.user);
});

app.listen(3000, () => {
  console.log("App is running on port 3000");
});
