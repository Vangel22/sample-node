const { getAll, getSingle, create, update, remove } = require("../models/blog");

const getAllPosts = async (req, res) => {
  try {
    const posts = await getAll(req.auth.id);
    return res.status(200).send(posts);
  } catch (err) {
    return res.status(err.status).send(err.error);
  }
};

const getSinglePost = async (req, res) => {
  try {
    const data = await getSingle(req.auth.id, req.params.id);
    if (!data) {
      return res.status(404).send("Post not found!");
    }
    return res.status(200).send(data);
  } catch (err) {
    return res.status(err.status).send(err.error);
  }
};

const createPost = async (req, res) => {
  try {
    const data = {
      ...req.body,
      user_id: req.auth.id,
    };

    console.log("data", data);

    const newPost = await create(data);
    return res.status(200).send(newPost);
  } catch (err) {
    return res.status(err.status).send(err.error);
  }
};

const updatePost = async (req, res) => {
  try {
    const data = {
      ...req.body,
      user_id: req.auth.id,
    };

    const newPost = await update(req.params.id, data);
    return res.status(200).send(newPost);
  } catch (err) {
    return res.status(err.status).send(err.error);
  }
};

const deletePost = async (req, res) => {
  try {
    await remove(req.params.id);
    return res.status(200).send(`Post with id removed: ${req.params.id}`);
  } catch (err) {
    return res.status(err.status).send(err.error);
  }
};

module.exports = {
  getAllPosts,
  getSinglePost,
  createPost,
  updatePost,
  deletePost,
};
