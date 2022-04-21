import express from 'express';
import { Request, Response } from 'express';
import dotenv from 'dotenv';
dotenv.config();

import {jwtMiddleware} from './middlewares/jwt-middleware';
import { encodeSession } from './helpers/jwtHelper';
import { Session } from './models/Session';

const app = express();

// Set up middleware to protect the protected route. This must come before routes
app.use('/protected', jwtMiddleware);

// If you want to protect _all_ routes instead of just /protected, uncomment the next line
// app.use(authMiddleware);

app.post("/sessions", (req: Request, res: Response) => {
    // This route is unprotected, anybody can call it
    // TODO: Validate username/password
    const session = encodeSession(process.env.JWT_SECRET_KEY!, {
        id: 23838,
        username: "some user",
        dateCreated: Date.now()
    });

    res.status(201).json(session);
});

// Set up an HTTP Get listener at /protected. The request can only access it if they have a valid JWT token
app.get('/protected', (req: Request, res: Response) => {
    // The auth middleware protects this route and sets res.locals.session which can be accessed here
    const session: Session = res.locals.session;

    res.status(200).json({message: `Your username is ${session.username}`});
})

app.listen(3000, () => {
    console.log("Server is listening on Port: ", 3000);
})