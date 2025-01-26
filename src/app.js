const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const port = 3000;
const SECRET_KEY = crypto.randomBytes(64).toString('hex'); // Generate a strong random key

app.use(bodyParser.json());

// Mock database
let users = [];
let products = [];
let carts = {};

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// User Registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { id: users.length + 1, username, password: hashedPassword };
    users.push(user);
    res.status(201).json({ message: 'User registered successfully' });
});

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (user == null) return res.status(400).json({ message: 'Cannot find user' });

    try {
        if (await bcrypt.compare(password, user.password)) {
            const accessToken = jwt.sign({ username: user.username, id: user.id }, SECRET_KEY);
            res.json({ accessToken });
        } else {
            res.json({ message: 'Password incorrect' });
        }
    } catch {
        res.status(500).json({ message: 'Error in authentication' });
    }
});

// Add and retrieve products
app.post('/products', authenticateToken, (req, res) => {
    const { name, price } = req.body;
    const id = products.length + 1;
    const product = { id, name, price };
    products.push(product);
    res.status(201).json(product);
});

app.get('/products', (req, res) => {
    res.status(200).json(products);
});

// Cart management
app.post('/cart', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { productId, quantity } = req.body;
    const product = products.find(p => p.id === productId);
    if (!product) return res.status(404).json({ message: 'Product not found' });

    if (!carts[userId]) {
        carts[userId] = [];
    }

    carts[userId].push({ productId, quantity });
    res.status(201).json({ message: 'Product added to cart', cart: carts[userId] });
});

app.get('/cart', authenticateToken, (req, res) => {
    const userId = req.user.id;
    res.status(200).json(carts[userId] || []);
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});