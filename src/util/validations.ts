import Joi from 'joi';

export const cardSchema = Joi.object({
    name: Joi.string().min(3).max(50).required(),
    status: Joi.string().min(3).max(30).required(),
    content: Joi.string().min(3).max(300).required(),
    category: Joi.string().min(3).max(50).required(),
    username: Joi.string().min(2).max(50).required(),
});

export const registrationSchema = Joi.object({
    username: Joi.string().min(2).max(50).required(),
});

export const cardIdSchema = Joi.object({
    cardId: Joi.number().required(),
});

// function validateSchema(schema: Joi.ObjectSchema) {
//     // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
//     return (req: express.Request, res: express.Response, next: express.NextFunction) => {
//         const { error } = schema.validate(req.body);
//         if (error) {
//             return res.status(400).json({ message: error.details[0].message });
//         }
//         next();
//     };
// }
