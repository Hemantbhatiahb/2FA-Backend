const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();

const generateToken = (email, expiresIn = "1d") => {
  const token = jwt.sign({ email }, process.env.JWT_SECRETKEY, {
    expiresIn,
  });
  console.log("Token generated:", token);
  return token;
};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const sendEmail = async (to, subject, html) => {
  // const transporter = nodemailer.createTransport({
  //   host: process.env.EMAIL_HOST,
  //   port: process.env.EMAIL_PORT,
  //   auth: {
  //     user: process.env.EMAIL_USER,
  //     pass: process.env.EMAIL_PASS,
  //   },
  // });

  // const mailOptions = {
  //   from: process.env.SENDER_EMAIL,
  //   to,
  //   subject,
  //   html,
  // };

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    html,
  };

  return await transporter.sendMail(mailOptions);
};

module.exports = { generateToken, sendEmail };
