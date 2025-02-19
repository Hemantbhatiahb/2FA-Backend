const jwt = require("jsonwebtoken");

const auth = (req, res, next) => {
  try {
    console.log("called auth middleware", req);
    const token = req.cookies.token;
    console.log("token: ", token);
    if (!token) {
      return res
        .status(400)
        .json({ success: false, message: "Token is missing!" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRETKEY);
    const userId = decoded.userId;
    req.body.userId = userId;
    next();
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Token is invalid, Try Login Again" });
  }
};

module.exports = auth;
