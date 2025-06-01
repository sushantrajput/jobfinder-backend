const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
const port = process.env.PORT || 8080;

// Environment logging for debugging
console.log("🔧 Environment Check:");
console.log("PORT:", process.env.PORT);
console.log("DATABASE_URL:", process.env.DATABASE_URL ? "✅ Set" : "❌ Missing");

// Allowed origins for CORS
const allowedOrigins = [
  "https://jobfinder-nu-virid.vercel.app",
  "http://localhost:3000",
  "http://localhost:3001"
];

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log("❌ CORS blocked origin:", origin);
      // callback(new Error(Origin ${origin} not allowed by CORS));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Origin", 
    "X-Requested-With", 
    "Content-Type", 
    "Accept", 
    "Authorization",
    "Access-Control-Allow-Origin"
  ],
  credentials: true,
  optionsSuccessStatus: 200
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// Parse JSON bodies
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  // console.log(${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.get('Origin') || 'None'});
  next();
});

// PostgreSQL connection
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false,
  } : false,
});

// Test database connection
db.query("SELECT NOW()")
  .then((result) => {
    console.log("✅ Database connected successfully");
    console.log("📅 Database time:", result.rows[0].now);
  })
  .catch((err) => {
    console.error("❌ Database connection failed:", err.message);
  });

// Health check route
app.get("/", (req, res) => {
  res.json({ 
    message: "JobFinder API is running",
    timestamp: new Date().toISOString(),
    port: port,
    cors: {
      allowedOrigins: allowedOrigins
    }
  });
});

// Health check route for Railway
app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK", uptime: process.uptime() });
});

// Signup route
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const username = name;
    // Validation
    if (!name?.trim() || !email?.trim() || !password) {
      return res.status(400).json({ 
        message: "All fields are required",
        received: { name: !!name, email: !!email, password: !!password }
      });
    }
    const cleanEmail = email.trim().toLowerCase();

    // Check if user already exists
    const existingUser = await db.query(
      "SELECT id FROM users WHERE email = $1 OR username = $2",
      [cleanEmail, username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ 
        message: "Email or username already exists" 
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user
    const result = await db.query(
      "INSERT INTO users (username, email, password, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, username, email, created_at",
      [username, cleanEmail, hashedPassword]
    );

    const newUser = result.rows[0];

    // console.log(✅ New user registered: ${newUser.email});

    res.status(201).json({ 
      message: "User registered successfully",
      userId: newUser.id
    });

  } catch (error) {
    console.error("❌ Signup error:", error.message);
    res.status(500).json({ 
      message: "Registration failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email?.trim() || !password) {
      return res.status(400).json({ 
        message: "Email and password are required" 
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // Find user
    const result = await db.query(
      "SELECT id, username, email, password, created_at FROM users WHERE email = $1",
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        message: "Invalid email or password" 
      });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ 
        message: "Invalid email or password" 
      });
    }

    // console.log("✅ User logged in:" ,${user.email});

    // Return user data (without password)
    res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at,
      },
    });

  } catch (error) {
    console.error("❌ Login error:", error.message);
    res.status(500).json({ 
      message: "Login failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("❌ Unhandled error:", err.message);
  
  if (err.message.includes('CORS')) {
    return res.status(403).json({ 
      message: "CORS policy violation",
      origin: req.get('Origin')
    });
  }
  
  res.status(500).json({ 
    message: "Internal server error",
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Handle 404 routes
app.use((req, res) => {
  res.status(404).json({ 
    message: "Route not found",
    path: req.path,
    method: req.method
  });
});

// Start server
app.listen(port, "0.0.0.0", () => {
  console.log("🚀 Server Status:");
  console.log(`   ✅ Listening on port ${port}`);
  console.log(`   🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   🔗 CORS origins: ${allowedOrigins.join(', ')}`);
  console.log(`   📡 Server URL: http://0.0.0.0:${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  db.end(() => {
    console.log('📡 Database connection closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  db.end(() => {
    console.log('📡 Database connection closed');
    process.exit(0);
  });
});