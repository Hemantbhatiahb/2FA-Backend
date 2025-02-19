const express = require("express");
const connectDB = require("./config/db");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const userRouter = require("./routes/userRoutes");

require("dotenv").config();

const app = express();

// middlewares
app.use(express.json());
app.use(express.static("public"));
app.use(cookieParser());
app.use(cors({ origin: "http://localhost:5173", credentials: true }));

connectDB();

// routes
app.use("/api/users", userRouter);

app.get("/", (req, res) => {
  res.send("hello");
});

const PORT = 8000;
app.listen(PORT, () => {
  console.log(`App is running on PORT:${PORT}`);
});
