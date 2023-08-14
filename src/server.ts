import bcrypt from 'bcrypt';
import crypto from 'crypto';
import express, { NextFunction, Request, Response } from 'express';
import Joi from 'joi';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { createConnection, getConnection } from 'typeorm';

import { Card, User } from './entities';
import { cardIdSchema, cardSchema, registrationSchema } from './util/validations';

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

function validateSchema(schema: Joi.ObjectSchema) {
    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
        const { error } = schema.validate(req.body);
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }
        next();
    };
}

function validateCardIdParam(schema: Joi.ObjectSchema) {
    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
        const { error } = schema.validate({ cardId: req.params.cardId });
        if (error) {
            return res.status(400).json({ message: 'Invalid cardId' });
        }
        next();
    };
}

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function authenticateToken(req: Request, res: Response, next: NextFunction) {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).send('Authorization token not provided');
    }

    try {
        const context = jwt.verify(token, secretKey) as AuthPayload;
        // Forward context info like username to request
        req.body.username = context.username;
        next();
    } catch (error) {
        return res.status(403).send('Invalid token');
    }
}

// Unprotected api to register a new user
app.post('/register', validateSchema(registrationSchema), async (req, res) => {
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

// Protected api: store cards
app.post('/cards', authenticateToken, validateSchema(cardSchema), async (req, res) => {
    const { name, status, content, category, username } = req.body;

    try {
        // Scope of improvement: Shift database things to models
        const user = await getConnection().getRepository(User).findOne({ username: username });

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

// Protected api: update card
app.put('/cards/:cardId', authenticateToken, validateCardIdParam(cardIdSchema), validateSchema(cardSchema), async (req, res) => {
    const { cardId } = req.params;
    const { name, status, content, category, username } = req.body;

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

// Protected api: delete card
app.delete('/cards/:cardId', authenticateToken, validateCardIdParam(cardIdSchema), async (req, res) => {
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
