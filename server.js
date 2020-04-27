const express       = require('express'),
      bodyParser    = require('body-parser'),
      dotenv        = require('dotenv').config(),
      mongoose      = require('mongoose'),
      sessions      = require('client-sessions'),
      bcrypt        = require('bcryptjs'),
      csurf         = require('csurf')

app = express();

app.use(bodyParser.urlencoded({ extended:false }))
app.use(sessions({
    cookieName:'session',
    secret:'secret82193810',
    duration:30*60*1000,
    activeDuration: 5*60*1000,
    httpOnly: true, // don't let JS code acess cookies
    // secure: true,   // only set cookies over https
    ephemeral: true // destroy cookies when the browser closes
}));

app.use((req,res,next) => {
    if(!(req.session && req.session.userId)) {
        return next();
    }

    User.findById(req.session.userId, (err, user) => {
        if(err) {
            return next(err);
        }
        if(!user) {
            return next();
        }
        user.password = undefined;
        req.user = user;
        res.locals.user = user;

        next();
    })
})

app.use(csurf())

app.set('view engine','pug');

// MONGOOSE SETUP
const connectionUrl = process.env.CONNECTIONURL

mongoose.connect(connectionUrl,{
    useNewUrlParser: true,
    useUnifiedTopology: true
})

UserSchema = new mongoose.Schema({
    firstName:   {type : String, required : true},
    lastName:    {type : String, required : true},
    email:       {type : String, required : true, unique : true},
    password:    {type : String, required : true}
})

var User = mongoose.model('User',UserSchema)

// ROUTES
app.get('/',(req,res)=>{
    res.render('index');
});

app.get('/register',(req,res)=>{
    res.render("register",{csrfToken: req.csrfToken()});
});

app.get('/login',(req,res)=>{
    res.render('login',
    {csrfToken: req.csrfToken()}
    );
});

app.post('/login',(req,res)=>{
    User.findOne({email:req.body.email},(err,user) => {
        if (err || !user || !bcrypt.compareSync(req.body.password, user.password)) {
            return res.render('login',{error:"Incorrect login/password"});
        }
        req.session.userId = user._id;
        res.redirect('dashboard');
    });
});


// app.get('/dashboard', loginRequired, (req,res,next => {...}))
app.get('/dashboard',(req,res,next)=>{
    if(!(req.session && req.session.userId)) {
        return res.redirect('login')
    }
    User.findById(req.session.userId, (err,user) => {
        if(err) {
            return next(err);
        }
        if(!user) {
            return res.redirect('/login')
        }
    })

    res.render('dashboard')
})

app.post('/register',(req,res)=>{
    let hash = bcrypt.hashSync(req.body.password, 14)
    req.body.password = hash
    let user = new User(req.body);

    user.save( err=>{
        if(err) {
            let error = 'Something bad happened! Please try again.';

            if (err.code === 11000) {
                error = "That email is already taken, please try another.";
            }
            console.log(err)
            return res.render('register',{error:error})
        }
        
        res.redirect('/dashboard');
    })
    
})




app.listen(3001, function(){
    console.log('Listing on port 3001!')
})


function loginRequired (req,res,next) {
    if(!req.user) {
        return redirect('/login');
    }
    next();
}