const mongoose = require("mongoose");
require("dotenv").config();

const DB_URL = process.env.DB_URL;

const connectDB = async () => {
  try {
    await mongoose.connect(DB_URL);
    console.log("Successfully connected to DB ");
  } catch (error) {
    console.log("Error connecting DB: ", error.message);
  }
};

module.exports = connectDB;
