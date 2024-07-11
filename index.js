const express = require("express");
const { expressjwt: jwt } = require("express-jwt");
require("dotenv").config();
const {
  login,
  register,
  refreshToken,
  resetPassword,
} = require("./handlers/auth");
const { getAllPosts, createPost } = require("./handlers/posts");

require("./config/db");

const app = express();

app.use(express.json());
app.use(
  jwt({
    secret: process.env.JWT_SECRET,
    algorithms: ["HS256"],
  }).unless({
    path: [
      "/api/auth/login",
      "/api/auth/register",
      "/api/auth/forgot-password",
      "/api/auth/reset-password",
    ],
  })
);

// Auth routes
app.post("/api/auth/login", login);
app.get("/api/auth/refresh-token", refreshToken);
app.post("/api/auth/register", register);
app.post("/api/auth/reset-password", resetPassword);

// Blog routes
app.get("/api/blog", getAllPosts);
app.post("/api/blog", createPost);

// server startup
app.listen(10000, () => {
  console.log(`Server started at port 10000!`);
});
