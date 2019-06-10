const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
// 1. Require bcrypt, after installing
const bcrypt = require('bcryptjs'); 

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

  // 2. Hash the password 
  const hash = bcrypt.hashSync(user.password, 8); // password gets re-hashed 2 ^ 8 times 

  // 3. Set password equal to hash
  user.password = hash; 

  // Code to add the user 
  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // Adding a check to verify if PW is same in if statement 
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

// Middleware to restrict access
function restricted(req, res, next) {
  // Read username and password from the headers
  const { username, password } = req.headers; 

  // Find user in db and verify 
  if (username && password) {
    Users.findBy({ username })
    .first()
    .then(user => {
      // Adding a check to verify if PW is same in if statement 
      if (user && bcrypt.compareSync(password, user.password)) {
        next(); 
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
  } else {
    res.status(400).json({message: 'Please provide valid credentials'})
  }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
