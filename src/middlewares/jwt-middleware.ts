import { Request, Response, NextFunction } from "express";
import { checkExpirationStatus, decodeSession, encodeSession } from "../helpers/jwtHelper";
import { DecodeResult, ExpirationStatus } from "../models/JWTResult";
import { Session } from "../models/Session";

/**
 * Express middleware, checks for a valid JSON Web Token and returns 401 Unauthorized if one isn't found.
 */
export function jwtMiddleware(request: Request, response: Response, next: NextFunction) {
     const unauthorized = (message: string) => response.status(401).json({
         success: false,
         status: 401,
         message: message
     });

     const requestHeader = "X-JWT-Token";
     const responseHeader = "X-Renewed-JWT-Token";
     const header = request.header(requestHeader);

     if (!header) {
         unauthorized(`Required ${requestHeader} header not found`);
         return;
     }

     const decodedSession : DecodeResult = decodeSession(process.env.JWT_SECRET_KEY!, header);

     if (decodedSession.type === 'integrity-error' || decodedSession.type === 'invalid-token' ) {
         unauthorized(`Failed to decode or validate authorization token, Reason: ${decodedSession.type}.`);
         return;
     }

     const expiration: ExpirationStatus = checkExpirationStatus(decodedSession.session);

     if (expiration === 'expired') {
         unauthorized('Authorization token has expired. Please create a new authorization token.');
         return;
     }

     let session: Session;

     if (expiration === 'grace') {
         /// Authomatically renew the session and send it back with the response 
         const {token, expires, issued} = encodeSession(process.env.JWT_SECRET_KEY!, decodedSession.session);
         session = {
             ...decodedSession.session,
             expires: expires,
             issued: issued
         };

         response.setHeader(responseHeader, token);
     } else {
         session = decodedSession.session;
     }

     /// set the session on response.locals object for routes to access
     response.locals = {
         ...response.locals,
         session: session
     }

     // Request has a valid or renewed session. Call next to continue to the authenticated route handler
     next();
}