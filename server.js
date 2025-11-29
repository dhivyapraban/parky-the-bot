require("dotenv").config();
const express = require("express");
const app = express();
app.set("trust proxy", 1);

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");

const { isAuthenticated } = require("./middleware/auth");


const { neon } = require("@neondatabase/serverless");
const sql = neon(process.env.DATABASE_URL);


const PORT = 3700;

app.use(express.json());
app.use("/img", express.static(path.join(__dirname, "public")));
// app.use(express.static("public"));
// app.use(sessionMiddleware);

// Home
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* ------------------ SIGNUP ------------------ */
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const existing = await sql`SELECT * FROM "User" WHERE email = ${email}`;
    if (existing.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await sql`
      INSERT INTO "User" (name, email, phone, password, "isGuest", feedback)
      VALUES (${name}, ${email}, ${phone}, ${hashed}, false, false)
      RETURNING *
    `;

    return res.status(200).json({
      message: "User registered successfully",
      data: user[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Signup failed" });
  }
});

/* ------------------ LOGIN ------------------ */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const users = await sql`SELECT * FROM "User" WHERE email = ${email}`;
    const user = users[0];
    
    if (!user) return res.status(404).json({ message: "User not found" });

    if (!user.password)
      return res.status(400).json({
        message: "This account does not have a password. Guest login is not supported."
      });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid password" });

    const botToken = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      process.env.SESSION_SECRET,
      { expiresIn: "1h" }
    );

    await sql`
      UPDATE "User" 
      SET "botToken" = ${botToken}
      WHERE email = ${email}
    `;

    return res.json({ botToken,name:user.name, message: "login successful" });

  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Login failed" });
  }
});

/* ------------------ TOKEN FETCH ------------------ */
app.post("/token", async (req, res) => {
  const { email } = req.body;

  if (!email)
    return res.status(400).json({ message: "Email ID is required" });

  const users = await sql`SELECT * FROM "User" WHERE email = ${email}`;
  const user = users[0];
  
  if (!user || !user.botToken)
    return res.status(404).json({ message: "Bot key not found or user not linked" });

  return res.json({ success: true, token: user.botToken });
});

/* ------------------ GUEST ------------------ */
app.get("/gue", isAuthenticated, (req, res) => {
  const name = req.user.name;
  res.status(200).json({ "name": name });
});

app.get("/me/name", isAuthenticated, (req, res) => {
  res.json({ name: req.user.name });
});

app.get("/favicon.ico", (req, res) => res.status(204).end());


/* ------------------ SERVER ------------------ */
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});