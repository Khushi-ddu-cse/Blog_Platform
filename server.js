const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const initSqlJs = require("sql.js");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "development-secret-change-before-deployment";
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "blog.db");
let db;

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

function saveDb() {
    fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function all(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
}

function one(sql, params = []) {
    return all(sql, params)[0];
}

function run(sql, params = []) {
    db.run(sql, params);
    saveDb();
}

function text(value) {
    return typeof value === "string" ? value.trim() : "";
}

function safeUser(user) {
    return {
        id: user.id,
        name: user.name,
        email: user.email,
        created_at: user.created_at
    };
}

function makeToken(user) {
    return jwt.sign(
        { id: user.id, name: user.name, email: user.email },
        SECRET,
        { expiresIn: "7d" }
    );
}

function auth(req, res, next) {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return res.status(401).json({ message: "Please log in first." });

    try {
        req.user = jwt.verify(token, SECRET);
        next();
    } catch {
        return res.status(401).json({ message: "Session expired. Please log in again." });
    }
}

app.post("/api/auth/register", async (req, res) => {
    try {
        const name = text(req.body.name);
        const email = text(req.body.email).toLowerCase();
        const password = typeof req.body.password === "string" ? req.body.password : "";

        if (name.length < 2) return res.status(400).json({ message: "Name must have at least 2 characters." });
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
        message: "Enter a valid email address."
    });
}
        if (password.length < 6) return res.status(400).json({ message: "Password must have at least 6 characters." });
        if (one("SELECT id FROM users WHERE email = ?", [email])) return res.status(409).json({ message: "This email is already registered." });

        const hash = await bcrypt.hash(password, 10);
        run("INSERT INTO users (name,email,password_hash,created_at) VALUES (?,?,?,?)",
            [name, email, hash, new Date().toISOString()]);
        const user = one("SELECT id,name,email,created_at FROM users WHERE email = ?", [email]);
        res.status(201).json({ token: makeToken(user), user: safeUser(user) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Could not create account." });
    }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const email = text(req.body.email).toLowerCase();
        const password = typeof req.body.password === "string" ? req.body.password : "";
        const user = one("SELECT * FROM users WHERE email = ?", [email]);
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ message: "Email or password is incorrect." });
        }
        res.json({ token: makeToken(user), user: safeUser(user) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Could not log in." });
    }
});

app.get("/api/auth/me", auth, (req, res) => {
    const user = one("SELECT id,name,email,created_at FROM users WHERE id = ?", [req.user.id]);
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json({ user: safeUser(user) });
});

app.get("/api/posts", (req, res) => {
    const search = text(req.query.search);
    const posts = all(
        `SELECT p.id,p.title,p.content,p.created_at,p.updated_at,
                u.id AS author_id,u.name AS author_name,
                (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count
         FROM posts p JOIN users u ON u.id=p.user_id
         WHERE (?='' OR p.title LIKE ? OR p.content LIKE ?)
         ORDER BY p.created_at DESC`,
        [search, `%${search}%`, `%${search}%`]
    );
    res.json({ posts });
});

app.get("/api/posts/:id", (req, res) => {
    const id = Number(req.params.id);
    const post = one(
        `SELECT p.id,p.title,p.content,p.user_id,p.created_at,p.updated_at,
                u.id AS author_id,u.name AS author_name
         FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?`, [id]
    );
    if (!post) return res.status(404).json({ message: "Post not found." });
    const comments = all(
        `SELECT c.id,c.post_id,c.content,c.created_at,u.id AS author_id,u.name AS author_name
         FROM comments c JOIN users u ON u.id=c.user_id
         WHERE c.post_id=? ORDER BY c.created_at ASC`, [id]
    );
    res.json({ post, comments });
});

app.post("/api/posts", auth, (req, res) => {
    const title = text(req.body.title);
    const content = text(req.body.content);
    if (title.length < 3 || title.length > 120) return res.status(400).json({ message: "Title must be 3 to 120 characters." });
    if (content.length < 10 || content.length > 20000) return res.status(400).json({ message: "Post content must be 10 to 20,000 characters." });

    const now = new Date().toISOString();
    run("INSERT INTO posts (title,content,user_id,created_at,updated_at) VALUES (?,?,?,?,?)",
        [title, content, req.user.id, now, now]);
    res.status(201).json({ post: one("SELECT * FROM posts WHERE id=last_insert_rowid()") });
});

app.put("/api/posts/:id", auth, (req, res) => {
    const id = Number(req.params.id);
    const post = one("SELECT * FROM posts WHERE id=?", [id]);
    if (!post) return res.status(404).json({ message: "Post not found." });
    if (post.user_id !== req.user.id) return res.status(403).json({ message: "You can only edit your own posts." });

    const title = text(req.body.title);
    const content = text(req.body.content);
    if (title.length < 3 || title.length > 120) return res.status(400).json({ message: "Title must be 3 to 120 characters." });
    if (content.length < 10 || content.length > 20000) return res.status(400).json({ message: "Post content must be 10 to 20,000 characters." });

    run("UPDATE posts SET title=?,content=?,updated_at=? WHERE id=?",
        [title, content, new Date().toISOString(), id]);
    res.json({ post: one("SELECT * FROM posts WHERE id=?", [id]) });
});

app.delete("/api/posts/:id", auth, (req, res) => {
    const id = Number(req.params.id);
    const post = one("SELECT * FROM posts WHERE id=?", [id]);
    if (!post) return res.status(404).json({ message: "Post not found." });
    if (post.user_id !== req.user.id) return res.status(403).json({ message: "You can only delete your own posts." });

    db.run("DELETE FROM comments WHERE post_id=?", [id]);
    db.run("DELETE FROM posts WHERE id=?", [id]);
    saveDb();
    res.json({ message: "Post deleted." });
});

app.post("/api/posts/:id/comments", auth, (req, res) => {
    const postId = Number(req.params.id);
    const content = text(req.body.content);
    if (!one("SELECT id FROM posts WHERE id=?", [postId])) return res.status(404).json({ message: "Post not found." });
    if (!content || content.length > 2000) return res.status(400).json({ message: "Comment must be 1 to 2,000 characters." });

    run("INSERT INTO comments (post_id,user_id,content,created_at) VALUES (?,?,?,?)",
        [postId, req.user.id, content, new Date().toISOString()]);
    const comment = one(
        `SELECT c.id,c.post_id,c.content,c.created_at,u.id AS author_id,u.name AS author_name
         FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id=last_insert_rowid()`
    );
    res.status(201).json({ comment });
});

app.delete("/api/comments/:id", auth, (req, res) => {
    const id = Number(req.params.id);
    const comment = one("SELECT * FROM comments WHERE id=?", [id]);
    if (!comment) return res.status(404).json({ message: "Comment not found." });
    if (comment.user_id !== req.user.id) return res.status(403).json({ message: "You can only delete your own comments." });
    run("DELETE FROM comments WHERE id=?", [id]);
    res.json({ message: "Comment deleted." });
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use("/api", (req, res) => res.status(404).json({ message: "API route not found." }));

async function start() {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        const SQL = await initSqlJs();
        db = fs.existsSync(DB_PATH)
            ? new SQL.Database(new Uint8Array(fs.readFileSync(DB_PATH)))
            : new SQL.Database();

        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (post_id) REFERENCES posts(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
        saveDb();

        app.listen(PORT, () => {
            console.log(`BlogSpace running at http://localhost:${PORT}`);
            console.log(`SQLite database: ${DB_PATH}`);
        });
    } catch (err) {
        console.error("Server startup failed:", err);
        process.exit(1);
    }
}
start();
