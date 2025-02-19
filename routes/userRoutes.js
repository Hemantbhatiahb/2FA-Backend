const express = require("express");
const {
  registerUser,
  loginUser,
  verifyEmail,
  enable2FA,
  verify2FA,
  disable2FA,
  resetPassword,
  forgotPassword,
  resendVerificationEmail,
  getCurrentUser,
  logoutUser,
  changePassword,
  updateUser
} = require("../controllers/userController");
const auth = require("../middlewares/authMiddleware");

const userRouter = express.Router();

userRouter.post("/register", registerUser);
userRouter.get("/verify-email", verifyEmail);
userRouter.post('/resend-verification', resendVerificationEmail)

userRouter.get('/current-user',auth, getCurrentUser);
userRouter.put('/update-user/:userId', updateUser);
userRouter.put('/change-password', auth, changePassword );

userRouter.post("/enable-2fa", enable2FA);
userRouter.post("/verify-2fA", verify2FA);
userRouter.post("/disable-2fa", disable2FA);


userRouter.post("/login", loginUser);
userRouter.post('/logout', logoutUser);
userRouter.post('/forgot-password', forgotPassword)
userRouter.post('/reset-password', resetPassword);

module.exports = userRouter;
