const router = require("express").Router();
const User = require("../models/User");
//libary to hash password to keep private even if database breached
const bcrypt = require("bcrypt");

//REGISTER
router.post("/register", async (req, res)=> {
    try{
        const salt = await bcrypt.genSalt(15); //10 is default //increases password security if >
        const hashPass = await bcrypt.hash(req.body.password, salt)
        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashPass,
        });

        const user = await newUser.save();
        res.status(200).json(user);

    } catch(err){
        res.status(500).json(err);
        
    }
});

//LOGIN
router.post("/login", async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (!user) {
        return res.status(400).json("Wrong credentials.");
        }


        const validated = await bcrypt.compare(req.body.password, user.password);
        //removes password from response.
        const {password, ...others } = user._doc;
        if (!validated) {
            return res.status(400).json("Wrong credentials.");
        }

        res.status(200).json(others);
    } catch (err) {
        res.status(500).json(err);
    }
});


module.exports = router;