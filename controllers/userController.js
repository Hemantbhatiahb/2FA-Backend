const User = require("../models/userModal");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const { generateToken, sendEmail } = require("../utils/emailService");

const secretKey = process.env.JWT_SECRETKEY;
const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser && existingUser.isVerified) {
      return res
        .status(200)
        .send({ success: false, message: "User already exists. Try Login" });
    }

    if (existingUser && !existingUser.isVerified) {
      return res.status(200).send({
        success: false,
        message: "User already exists. Please verify your email",
      });
    }

    // Generate JWT
    const verificationToken = generateToken(email, "1d");
    console.log("Token generated:", verificationToken);

    // Send verification email
    const text = `<p>Click the link to verify: <a href="${process.env.BASE_URL}/api/users/verify-email?token=${verificationToken}">Verification Link</a></p>`;
    await sendEmail(email, "Verify your email", text);
    console.log("Email sent");

    const newUser = new User({ name, email, password });
    await newUser.save();

    return res.status(200).send({
      success: true,
      message: "User registered successfully. Please verify your email.",
    });
  } catch (error) {
    return res.status(500).send({ success: false, message: error.message });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(200)
        .json({ success: false, message: "User not found, Please register" });
    }

    if (!user.isVerified) {
      return res.status(200).json({
        success: false,
        message: "User not verified, Please verify your email",
      });
    }

    // compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(200)
        .json({ success: false, message: "Incorrect Password" });
    }

    if (user.is2FAEnabled) {
      return res.status(200).json({
        success: true,
        message: "Enter OTP to continue",
        requires2FA: true,
      });
    }

    // generate token
    const token = jwt.sign({ userId: user._id }, secretKey, {
      expiresIn: "1d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure:false,
      sameSite: "Lax",
      maxAge: 24 * 60 * 60 * 1000, // Expires in 1 day
    });

    return res.status(200).json({ success: true, message: "Login successful" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;

    // verify token
    const decoded = jwt.verify(token, secretKey);
    const user = await User.findOne({ email: decoded.email });

    if (!user) {
      return res
        .status(200)
        .json({ success: false, message: "User not found" });
    }

    if (user.isVerified) {
      return res
        .status(200)
        .json({ success: false, message: "Email already verified. Try Login" });
    }

    user.isVerified = true;
    await user.save();

    return res
      .status(200)
      .send({ success: true, message: "Email verified, You can login now" });
  } catch (error) {
    return res
      .status(500)
      .send({ success: false, message: `${error.message}, Try Again` });
  }
};

const enable2FA = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(200)
        .send({ success: false, message: "User not found" });
    }

    const secret = speakeasy.generateSecret({ name: `2FA-${email}` });

    user.twoFactorSecret = secret.base32;

    await user.save();

    qrcode.toDataURL(secret.otpauth_url, (err, qrCodeImage) => {
      if (err) {
        return res
          .status(200)
          .json({ success: false, message: "QR code generation failed" });
      }

      return res.status(200).json({
        success: true,
        message: "Scan this QR code with google authenticator",
        data: qrCodeImage,
      });
    });
  } catch (error) {
    return res.status(500).send({ success: false, message: error.message });
  }
};

const verify2FA = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(200)
        .json({ success: false, message: "2FA is not enabled" });
    }

    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token: otp,
      window: 2,
    });

    if (!isValid) {
      return res.status(200).json({ success: false, message: "Invalid OTP" });
    }

    const token = jwt.sign({ userId: user._id }, secretKey, {
      expiresIn: "1d",
    });

    user.is2FAEnabled = true;
    const newUser = await User.findByIdAndUpdate(
      user._id,
      { is2FAEnabled: true },
      { new: true }
    );

    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // Expires in 1 day
    });

    return res.status(200).json({
      success: true,
      message: "2FA verified, login successful",
      data: newUser,
    });
  } catch (error) {
    return res.status(500).send({ success: false, message: error.message });
  }
};

const disable2FA = async (req, res) => {
  try {
    const { userId } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { is2FAEnabled: false, twoFactorSecret: null },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(200).json({
        success: false,
        message: "User not found, Please Login Again",
      });
    }

    return res.status(200).json({
      success: true,
      message: "2FA disabled successfully",
      data: updatedUser,
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

const resendVerificationEmail = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.isVerified) {
      return res.status(200).json({
        success: false,
        message: "User is already verified.",
      });
    }

    const verificationToken = generateToken(email, "1d");
    console.log("Token generated:", verificationToken);

    // Send verification email
    const text = `<p>Click the link to verify: <a href="${process.env.BASE_URL}/api/users/verify-email?token=${verificationToken}">Verification Link</a></p>`;
    await sendEmail(email, "Verify your email", text);
    console.log("Email sent");

    return res.status(200).json({
      success: true,
      message: "Verification email sent again. Please check your inbox.",
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found" });
    }

    if (!user.isVerified) {
      return res
        .status(400)
        .json({ success: false, message: "User is not verified" });
    }

    // Generate reset token
    const resetToken = jwt.sign({ email }, process.env.JWT_SECRETKEY, {
      expiresIn: "15m",
    });

    // Send password reset email
    const resetLink = `http://localhost:5173/reset-password?token=${resetToken}`;
    const text = `<p>Click the link to reset your password: <a href="${resetLink}">Reset Password</a></p>`;

    await sendEmail(email, "Reset Your Password", text);

    return res.status(200).json({
      success: true,
      message: "Password reset link sent to your email.",
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRETKEY);
    const user = await User.findOne({ email: decoded.email });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found" });
    }

    // Update password
    user.password = newPassword;
    await user.save();

    return res
      .status(200)
      .json({ success: true, message: "Password reset successfully." });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Invalid or expired token. Try again" });
  }
};

const getCurrentUser = async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId).select("-password");
    return res.send({
      success: true,
      message: "You are authenticated!",
      data: user,
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

const updateUser = async (req, res) => {
  try {
    const {userId} = req.params;
    if (!userId) {
      return res
        .status(200)
        .json({ success: false, message: "UserId missing" });
    }
    const newUser = await User.findByIdAndUpdate(userId, req.body, {
      new: true,
    });
    if (!newUser) {
      return res
        .status(200)
        .json({ success: false, message: "User not found" });
    }
    return res.status(200).json({
      success: true,
      message: "User updated successfully",
      data: newUser,
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

const changePassword = async (req, res) => {
  try {
    const { userId, oldPassword, newPassword } = req.body;
    const user = await User.findById(userId);

    if(!userId || !oldPassword || !newPassword ) {
      return res
        .status(200)
        .json({ success: false, message: "Fields are missing" });
    }
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // verify old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ success: false, message: "Incorrect old password" });
    }
    user.password = newPassword;
    await user.save();

    return res
      .status(200)
      .json({ success: true, message: "Password updated successfully!" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

const logoutUser = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    return res
      .status(200)
      .json({ success: true, message: "Logged out successfully." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Logout failed." });
  }
};

module.exports = {
  registerUser,
  loginUser,
  verifyEmail,
  resendVerificationEmail,
  disable2FA,
  enable2FA,
  verify2FA,
  forgotPassword,
  resetPassword,
  getCurrentUser,
  logoutUser,
  updateUser,
  changePassword,
};
