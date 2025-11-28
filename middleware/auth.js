// function isAuthenticated(req, res, next) {
//     if (req.session && req.session.user) return next();
//     return res.status(401).json({ message: "Unauthorized" });
// }

const jwt = require("jsonwebtoken");

function isAuthenticated(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1]; // Bearer <token>
  if (!token) return res.status(401).json({ message: "Invalid token format" });

  jwt.verify(token, process.env.SESSION_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });

    req.user = decoded; // attach user info to request
    next();
  });
}

module.exports = { isAuthenticated };
