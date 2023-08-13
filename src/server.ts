import bcrypt from 'bcrypt';
import crypto from 'crypto';
import express from 'express';
import jwt from 'jsonwebtoken';
import { createConnection, getConnection } from 'typeorm';

import { User } from './entities/User';

const app = express();
const port = 3000;
const secretKey = 'yourSecretKey';

app.use(express.json());

// Random password generator for user
function generatePassword(username: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(username);
    return hash.digest('hex');
}

createConnection()
    .then(() => {
        console.log('Connected to the database');
    })
    .catch((error) => console.error('Error connecting to the database:', error));

// Endpoint to register a new user
app.post('/register', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).send('Username is required.');
    }

    const password = generatePassword(username);
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const user = new User();
    user.username = username;
    user.passwordHash = hashedPassword;

    await getConnection().getRepository(User).save(user);

    const token = jwt.sign({ username }, secretKey);
    return res.json({ message: 'User registered successfully', token });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
