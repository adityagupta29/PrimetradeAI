const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, initDb } = require('./database');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'super_secret_key_for_assignment'; // In production, use .env

// Middleware
app.use(cors());
app.use(express.json());

// Serve Frontend Files
app.use(express.static(path.join(__dirname, '../public')));

// --- AUTH ROUTES ---

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        if (!username || !email || !password) return res.status(400).json({ message: "All fields required" });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const stmt = db.prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)');
        stmt.run(username, email, hashedPassword, role || 'user');
        
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: "Email or Username already exists" });
        }
        res.status(500).json({ error: err.message });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

        if (!user) return res.status(400).json({ message: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        
        res.json({ 
            token, 
            user: { id: user.id, username: user.username, role: user.role } 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- MIDDLEWARE FOR PROTECTION ---
const protect = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Not authorized" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { id, role }
        next();
    } catch (err) {
        res.status(401).json({ message: "Invalid token" });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: "Forbidden: Admin access only" });
        }
        next();
    };
};

// --- TASK ROUTES (CRUD) ---

// Get Tasks (User sees their own, Admin sees all)
app.get('/api/tasks', protect, (req, res) => {
    let tasks;
    if (req.user.role === 'admin') {
        tasks = db.prepare(`
            SELECT tasks.*, users.username 
            FROM tasks 
            JOIN users ON tasks.user_id = users.id
        `).all();
    } else {
        tasks = db.prepare('SELECT * FROM tasks WHERE user_id = ?').all(req.user.id);
    }
    res.json(tasks);
});

// Create Task
app.post('/api/tasks', protect, (req, res) => {
    const { title, description } = req.body;
    const stmt = db.prepare('INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)');
    const result = stmt.run(title, description, req.user.id);
    res.status(201).json({ id: result.lastInsertRowid, title, description, status: 'pending' });
});

// Delete Task
app.delete('/api/tasks/:id', protect, (req, res) => {
    // Security: Check if user owns the task or is admin
    const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(req.params.id);
    
    if (!task) return res.status(404).json({ message: "Task not found" });
    
    if (task.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ message: "Not authorized to delete this task" });
    }

    db.prepare('DELETE FROM tasks WHERE id = ?').run(req.params.id);
    res.json({ message: "Task deleted" });
});

// --- ADMIN ROUTE ---
app.get('/api/admin/users', protect, authorize('admin'), (req, res) => {
    const users = db.prepare('SELECT id, username, email, role FROM users').all();
    res.json(users);
});

// Start Server
initDb();
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}/index.html`);
});