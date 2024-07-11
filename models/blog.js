const mongoose = require("mongoose");

const postSchema = mongoose.Schema({
  user_id: {
    type: mongoose.SchemaTypes.ObjectId,
    ref: "Account",
  },
  title: String,
  content: String,
});

const Posts = mongoose.model("Post", postSchema, "posts");

// req.auth
const getAll = async (user_id) => {
  return await Posts.find({ user_id });
};

const getSingle = async (user_id, id) => {
  return await Posts.find({ _id: id, user_id });
};

const getAllAlphabetically = async (user_id) => {};

const create = async (data) => {
  const post = new Posts(data);
  return await post.save();
};

const update = async (id, data) => {
  return await Posts.updateOne({ _id: id }, data);
};

const remove = async (id) => {
  return await Posts.deleteOne({ _id: id });
};

module.exports = {
  getAll,
  getSingle,
  getAllAlphabetically,
  create,
  update,
  remove,
};
