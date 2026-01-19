const express = require('express');
const User = require('./models');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const auth = require('./middleware/auth');
const role = require('./middleware/role');
const router = express.Router();

// User login
router.post('/login', async (req, res) => {
    try {
        const {email, password} = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ msg: 'Please enter all fields' });
        }

        const user = await User.findOne({email});
        if (!user) {
            return res.status(400).json({ msg: 'User does not exist' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch)
            return res.status(400).json({ msg: 'Invalid credentials' });

        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: 3600 }
        )

        res.json({
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            token
        });
    }
    catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// User signup
router.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const role = req.body.role === 'admin' ? 'user' : 'user';

        if (!name || !email || !password) {
            return res.status(400).json({ msg: 'Please enter all fields' });
        }

        const existingUser = await User.findOne({email});
        if (existingUser) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            name,
            email,
            password: hashedPassword, // Assume hashedPassword is defined elsewhere
            role: role
        });

        res.json({
            id: newUser._id,
            name: newUser.name,
            email: newUser.email
        })
    }
    catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// Create a new admin user (admin only)
router.post('/create-admin', auth, role('admin'), async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) 
            return res.status(400).json({ msg: 'Please enter all fields' });

        const existingUser = await User.findOne({email});
        if (existingUser)
            return res.status(400).json({ msg: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newAdmin = await User.create({
            name,
            email,
            password: hashedPassword,
            role: 'admin'
        });

        res.json({
            id: newAdmin._id,
            name: newAdmin.name,
            email: newAdmin.email,
            role: newAdmin.role
        });
    }
    catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});


// Get list of all users (admin only)
router.get('/list', auth, role('admin'), async (req, res) => {
    try {
        const users = await User.find({role: 'user'}).select('-password');
        res.json(users);
    }
    catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// Delete a user by ID (admin only)
router.delete('/:id', auth, role('admin'), async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        
        if (!user) 
            return res.status(404).json({ msg: 'User not found' });
        
        await user.remove();
        res.json({ msg: 'User deleted', user });
    }
    catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// Update user details (self-update only)
router.put("/me/update", auth, async (req, res) => {
  if (req.user.id !== req.params.id)
    return res.status(403).json({ message: "Unauthorized" });

  const { name, email } = req.body;

  const updatedUser = await User.findByIdAndUpdate(
    req.params.id,
    { name, email },
    { new: true, runValidators: true }
  ).select("-password");

  res.json(updatedUser);
});

// Get user details by ID (self-access only)
router.get("/me", auth,async (req, res) => {
    const user = await User.findById(req.user.id).select("name email");
    res.json({ message: `Welcome ${user.name}  ${user.email}` });
});


module.exports = router;
