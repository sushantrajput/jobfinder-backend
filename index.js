const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
const port = process.env.PORT || 3001;

// CORS setup
app.use(cors({
  origin: ["https://jobfinder-nu-virid.vercel.app", "http://localhost:3000"],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true
}));

app.use(express.json());

// Database connection
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Routes
app.get("/", (req, res) => {
  res.json({ message: "Server running" });
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  
  const existingUser = await db.query("SELECT * FROM users WHERE email = $1 OR username = $2", [email, name]);
  
  if (existingUser.rows.length > 0) {
    return res.status(409).json({ message: "Email or username already taken" });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  await db.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [name, email, hashedPassword]);
  
  res.status(201).json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  
  const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  
  if (result.rows.length === 0) {
    return res.status(401).json({ message: "Invalid email or password" });
  }
  
  const user = result.rows[0];
  const isMatch = await bcrypt.compare(password, user.password);
  
  if (!isMatch) {
    return res.status(401).json({ message: "Invalid email or password" });
  }
  
  res.status(200).json({
    message: "Login successful",
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      created_at: user.created_at,
    },
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});