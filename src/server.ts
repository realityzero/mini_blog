import bcrypt from 'bcrypt';
import crypto from 'crypto';
import express from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { createConnection, getConnection } from 'typeorm';

import { Card, User } from './entities';

// import { Card } from './entities/Card';
// import { User } from './entities/User';

const app = express();
const port = 3000;
const secretKey = 'yourSecretKey';

app.use(express.json());

interface AuthPayload extends JwtPayload {
    username: string;
}

// Random password generator for user
function generatePassword(username: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(username);
    return hash.digest('hex');
}

createConnection()
    .then(() => {
        console.log('Connected to database');
    })
    .catch((error) => console.error('Error connecting to database:', error));

// Unprotected api to register a new user
app.post('/register', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).send('Username is required');
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

app.post('/cards', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).send('Authorization token not provided');
    }

    const { name, status, content, category, username } = req.body;

    // TODO: will be replaced w/ joi
    if (!name || !status || !content || !category || !username) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        jwt.verify(token, secretKey) as AuthPayload;
        const user = await getConnection().getRepository(User).findOne({ username });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const card = new Card();
        card.name = name;
        card.status = status;
        card.content = content;
        card.category = category;
        card.user = user;

        await getConnection().getRepository(Card).save(card);

        return res.status(201).json({ message: 'Card created successfully' });
    } catch (error) {
        return res.status(500).json({ message: 'Error while creating the card' });
    }
});

app.put('/cards/:cardId', async (req, res) => {
    const { cardId } = req.params;
    const { name, status, content, category, username } = req.body;

    if (!name || !status || !content || !category || !username) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const card = await getConnection()
            .getRepository(Card)
            .findOne(cardId, { relations: ['user'] });

        if (!card) {
            return res.status(404).json({ message: 'Card not found' });
        }

        if (card.user.username !== username) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        card.name = name;
        card.status = status;
        card.content = content;
        card.category = category;

        await getConnection().getRepository(Card).save(card);

        return res.status(200).json({ message: 'Card updated successfully' });
    } catch (error) {
        return res.status(500).json({ message: 'Error while updating the card' });
    }
});

app.delete('/cards/:cardId', async (req, res) => {
    const { cardId } = req.params;
    const { username } = req.body;

    try {
        const card = await getConnection()
            .getRepository(Card)
            .findOne(cardId, { relations: ['user'] });

        if (!card) {
            return res.status(404).json({ message: 'Card not found' });
        }

        if (card.user.username !== username) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        await getConnection().getRepository(Card).remove(card);

        return res.status(200).json({ message: 'Card deleted successfully' });
    } catch (error) {
        return res.status(500).json({ message: 'Error while deleting the card' });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
