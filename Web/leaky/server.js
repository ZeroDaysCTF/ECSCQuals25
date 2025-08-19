const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bot = require('./bot');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: './'
    }),
    secret: require('crypto').randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'self'; script-src 'none'");
    next();
});

const db = new sqlite3.Database('./app.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS todos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
});

const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login', { error: req.query.error });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.redirect('/login?error=Username and password required');
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.redirect('/login?error=Invalid credentials');
        }

        try {
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.redirect('/login?error=Invalid credentials');
            }

            req.session.userId = user.id;
            req.session.username = user.username;
            res.redirect('/dashboard');
        } catch (error) {
            res.redirect('/login?error=Login failed');
        }
    });
});

app.get('/register', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('register', { error: req.query.error });
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.redirect('/register?error=Username and password required');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
            [username, hashedPassword], 
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.redirect('/register?error=Username already exists');
                    }
                    return res.redirect('/register?error=Registration failed');
                }
                
                req.session.userId = this.lastID;
                req.session.username = username;
                res.redirect('/dashboard');
            }
        );
    } catch (error) {
        res.redirect('/register?error=Registration failed');
    }
});

app.get('/dashboard', requireAuth, (req, res) => {
    let searchTerm = req.query.s || '';
    
    if (typeof searchTerm !== 'string') {
        searchTerm = '';
    }
    
    let query = 'SELECT * FROM todos WHERE user_id = ?';
    let params = [req.session.userId];

    if (searchTerm) {
        query += ' AND (title GLOB ? OR content GLOB ?)';
        const searchGlob = `*${searchTerm}*`;
        params.push(searchGlob, searchGlob);
    }

    query += ' ORDER BY created_at DESC';

    db.all(query, params, (err, todos) => {
        if (err) {
            return res.render('dashboard', { 
                username: req.session.username, 
                todos: [], 
                searchTerm: searchTerm,
                error: 'Failed to load todos'
            });
        }
        
        res.render('dashboard', { 
            username: req.session.username, 
            todos: todos, 
            searchTerm: searchTerm
        });
    });
});

app.post('/add-todo', requireAuth, (req, res) => {
    const { title, content } = req.body;
    
    if (!title) {
        return res.redirect('/dashboard?error=Title is required');
    }

    db.run('INSERT INTO todos (user_id, title, content) VALUES (?, ?, ?)', 
        [req.session.userId, title, content || ''], 
        function(err) {
            if (err) {
                return res.redirect('/dashboard?error=Failed to add todo');
            }
            res.redirect('/dashboard');
        }
    );
});

app.post('/delete-todo', requireAuth, (req, res) => {
    const { id } = req.body;
    
    db.run('DELETE FROM todos WHERE id = ? AND user_id = ?', 
        [id, req.session.userId], 
        function(err) {
            if (err) {
                return res.redirect('/dashboard?error=Failed to delete todo');
            }
            res.redirect('/dashboard');
        }
    );
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/report', requireAuth, (req, res) => {
    res.render('report', { 
        username: req.session.username,
        message: req.query.message,
        error: req.query.error 
    });
});

app.post('/report', requireAuth, async (req, res) => {
    const { url } = req.body;
    
    if (!url) {
        return res.redirect('/report?error=URL is required');
    }
    
    try {
        new URL(url);
    } catch (error) {
        return res.redirect('/report?error=Invalid URL format');
    }
    
    try {
        const success = await bot.visit(url);
        
        if (success) {
            res.redirect('/report?message=URL visited successfully by admin bot');
        } else {
            res.redirect('/report?error=Failed to visit URL');
        }
        
    } catch (error) {
        console.error('Error visiting URL:', error);
        res.redirect('/report?error=Failed to visit URL: ' + error.message);
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 