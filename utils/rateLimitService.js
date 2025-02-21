const rateLimit = require("express-rate-limit");

const rateLimiter = (windowMs, maxAttempts, message) => {
  return rateLimit({
    windowMs, // time for each window
    max: maxAttempts, // max number of requests
    headers: true,
    handler: (req, res) => {
      res.status(429).json({ message, success: false });
    },
  });
};

module.exports = rateLimiter;
