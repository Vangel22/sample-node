const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const { create, getByEmail, setNewPassword } = require("../models/account");

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const account = await getByEmail(email);

    if (!account) {
      return res.status(400).send("Account not found!");
    }

    if (!bcrypt.compareSync(password, account.password)) {
      return res.status(400).send("Wrong password!");
    }

    const payload = {
      fullName: account.fullName,
      email: account.email,
      id: account._id,
      exp: new Date().getTime() / 1000 + 7 * 24 * 60 * 60, // 7 dena vo idnina
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET);

    return res.status(200).send({ token });
  } catch (err) {
    res.status(500).send("Internal Server Error");
  }
};

const register = async (req, res) => {
  try {
    const { email, password, confirmPassword, fullName } = req.body;
    const exists = await getByEmail(email);
    if (exists) {
      return res.status(400).send("Account with this email already exists!");
    }
    if (password !== confirmPassword) {
      return res
        .status(400)
        .send("Confirm password is not the same as password!");
    }
    req.body.password = bcrypt.hashSync(password);
    const acc = await create(req.body);
    return res.status(201).send(acc);
  } catch (err) {
    console.log(err);
    return res.status(err.status).send(err.error);
  }
};

const refreshToken = async (req, res) => {
  const payload = {
    ...req.auth,
    exp: new Date().getTime() / 1000 + 7 * 24 * 60 * 60,
  };

  const token = jwt.sign(payload, process.env.JWT_SECRET);
  return res.status(200).send({ token }); // req.auth
};

const resetPassword = async (req, res) => {
  const { newPassword, oldPassword, email } = req.body;

  const account = await getByEmail(email);

  console.log("account data", account);

  if (!account) {
    return res.status(400).send("Account with this email does not exist!");
  }

  if (!bcrypt.compareSync(oldPassword, account.password)) {
    return res.status(400).send("Incorrect old password!");
  }

  if (newPassword === oldPassword) {
    return res.status(400).send("New password cannot be old password!");
  }

  const newPasswordHashed = bcrypt.hashSync(newPassword);

  const userPasswordChanged = await setNewPassword(
    account._id.toString(),
    newPasswordHashed
  );
  console.log("userPass", userPasswordChanged);

  return res.status(200).send(userPasswordChanged);
};

const forgotPassword = async (req, res) => {
  const exists = await getByEmail(req.body.email);
  if (!exists) {
    return res.status(400).send("Account with this email does not exist!");
  }

  res.send("OK");
};

module.exports = {
  login,
  register,
  resetPassword,
  forgotPassword,
  refreshToken,
};
