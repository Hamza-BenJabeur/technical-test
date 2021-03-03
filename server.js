const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')
const app = express();
const bodyParser = require('body-parser');
app.use(bodyParser.json());
let port=3000
//fake data
const users = [];
const admins=[];
const publicFiles=[];
const usersFiles=[];

//home page 
app.get('/api', (req, res) => {
  res.json({
    message: 'Welcome to the API'
  });
});

//fetch all users
app.get('/api/users', (req, res) => {
  res.json(users)
})

//fetch all admins
app.get('/api/admins',(req,res)=>{
  res.json(admins)
})


//create  users 
app.post('/api/users', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const user = { username: req.body.username, password: hashedPassword }
    users.push(user)
    res.status(201).send("success")
  } catch {
    res.status(500).send("try again")
  }
})



//create admins
app.post('/api/admins', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const admin = { username: req.body.username, password: hashedPassword }
    admins.push(admin)
    res.status(201).send("success")
  } catch {
    res.status(500).send("try again")
  }
})




//get users files
app.get('/api/users/files',(req,res)=>{
  res.json({usersFiles});
})



//get all public files 
app.get('api/publicFiles',(req,res)=>{
  res.json({publicFiles})
})


//add file(users)
app.post('/api/users/files', verifyToken, (req, res) => {  
  jwt.verify(req.token, 'secretkey', (err, Data) => {
    if(err) {
      res.sendStatus(403);
    } else {
      usersFiles.push(req.body);
      res.json({
        message: 'file added...',
        Data
        
      });
    }
  });
});

//add file(admins)
app.post('/api/admins/files', verifyToken, (req, res) => {  
  jwt.verify(req.token, 'secretkey', (err, Data) => {
    if(err) {
      res.sendStatus(403);
    } else {
      publicFiles.push(req.body);
      res.json({
        message: 'file added...',
        Data
        
      });
    }
  });
});


//users's authentication
app.post('/api/auth/users', async(req, res) => {
  const user = users.find(user => user.username === req.body.username)
  if (user == null) {
    return res.status(400).send('Cannot find user')
  }
  try {
  
    if(await bcrypt.compare(req.body.password, user.password)) {
     
      jwt.sign({
        id: req.body.id, 
        username: req.body.username,
        email:req.body.email
      }
      , 'secretkey', async (err, token) => {

        await res.json({
          token,...{
            id: req.body.id, 
            username: req.body.username,
            email:req.body.email
          },role:"user"
        });
      });
    } else {
      res.send('Not Allowed')
    }
  } catch {
    res.status(500).send("nothing is working")
  }

 
});




//admin's authentication
app.post('/api/auth/admins', async (req, res) => {
  const admin = admins.find(admin => admin.username === req.body.username)
  if (admin == null) {
    return res.status(400).send('Cannot find admin')
  }
  try {
  
    if(await bcrypt.compare(req.body.password, admin.password)) {
     
      jwt.sign({
        id: req.body.id, 
        username: req.body.username,
        email:req.body.email
      }
      , 'secretkey', async (err, token) => {

        await res.json({
          token,...{
            id: req.body.id, 
            username: req.body.username,
            email:req.body.email
          },role:"admin"
        });
      });
    } else {
      res.send('Not Allowed')
    }
  } catch {
    res.status(500).send("nothing is working")
  }
});



// Verify Token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if(typeof bearerHeader !== 'undefined') {
    const bearer = bearerHeader.split(' ');
    const bearerToken = bearer[1];
    req.token = bearerToken;
    next();
  } else {
    res.sendStatus(403);
  }

}

app.listen(port, () => console.log(`Server started on port ${port}`));