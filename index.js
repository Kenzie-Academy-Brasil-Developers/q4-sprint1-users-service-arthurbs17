import express from 'express';
import dotenv from 'dotenv';
import * as yup from 'yup';
import { v4 as uuid4 } from 'uuid';
import bcrypt from 'bcrypt';
import jsonwebtoken from 'jsonwebtoken';
import expressListRoutes from 'express-list-routes';

dotenv.config();

const app = express();
const PORT = process.env.PORT ? process.env.PORT : 3000;
const MY_SECRET = process.env.SECRET_KEY;

app.use(express.json());

const DB_USERS = [];

// SHAPES
const userShape = yup.object().shape({
  uuid: yup.string().default(() => uuid4()),
  username: yup.string().required(),
  age: yup.number().positive().integer().required(),
  email: yup.string().email().required(),
  password: yup
    .string()
    .required()
    .transform((pwd) => bcrypt.hashSync(pwd, 10)),
  createdOn: yup.date().default(() => new Date()),
});

const loginShape = yup.object().shape({
  username: yup.string().required(),
  password: yup.string().required(),
});

const changePasswordShape = yup.object().shape({
  password: yup
    .string()
    .required()
    .transform((pwd) => bcrypt.hashSync(pwd, 10)),
});

// MIDDLEWARES
const verifyRequest = (shape) => async (req, res, next) => {
  try {
    const user = await shape.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });
    req.verifyBody = user;
    return next();
  } catch (e) {
    return res.status(422).json({ message: e.errors[0] });
  }
};

const getUserbyUuid = (req, res, next) => {
  const { uuid } = req.params;
  const user = DB_USERS.find((u) => u.uuid === uuid);

  if (!user) {
    return res.status(404).json({ message: 'user not found' });
  }

  req.user = user;
  return next();
};

const validateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  jsonwebtoken.verify(token, MY_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: err });
    }

    if (decoded.user !== req.user.username) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    return next();
  });
};

const verifyExistsEmail = (req, res, next) => {
  const { email } = req.verifyBody;

  if (DB_USERS.find((user) => user.email === email)) {
    return res.status(409).json({ error: 'email already exists' });
  }

  return next();
};

// ROUTES
app.post('/signup', verifyRequest(userShape), verifyExistsEmail, (req, res) => {
  const user = { ...req.verifyBody };
  DB_USERS.push(user);
  const response = {
    uuid: user.uuid,
    createdOn: user.createdOn,
    email: user.email,
    age: 18,
    username: user.username,
  };

  return res.status(201).json(response);
});

app.post('/login', verifyRequest(loginShape), async (req, res) => {
  const credentials = { ...req.verifyBody };

  const user = DB_USERS.find((u) => u.username === credentials.username);

  if (!user) {
    return res.status(404).json({ error: 'wrong credentials!' });
  }

  const hashedPassword = await bcrypt.compare(
    credentials.password,
    user.password
  );

  if (!hashedPassword) {
    return res.status(404).json({ error: 'wrong credentials!' });
  }

  const token = jsonwebtoken.sign({ user: user.username }, MY_SECRET, {
    expiresIn: '1h',
  });

  return res.status(200).json({ token });
});

app.get('/users', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  jsonwebtoken.verify(token, MY_SECRET, (err) => {
    if (err) {
      return res.status(401).json({ error: err });
    }
    return res.status(200).json(DB_USERS);
  });
});

app.put(
  '/users/:uuid/password',
  verifyRequest(changePasswordShape),
  getUserbyUuid,
  validateToken,
  (req, res) => {
    req.user.password = req.verifyBody.password;

    return res.status(204).json();
  }
);

expressListRoutes(app);

app.listen(PORT, () => {
  console.log(`APP is running on port ${PORT}`);
});
