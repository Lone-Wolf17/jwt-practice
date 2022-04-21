export interface Session {
    id: number;
    dateCreated: number;
    username: string;

     /**
     * Timestamp indicating when the session was created, in Unix milliseconds.
     */
    issued: number;

     /**
     * Timestamp indicating when the session should expire, in Unix milliseconds.
     */
    expires: number
}


/**
 * Identical to the Session type, but without the `issued` and `expires` properties.
 */
export type PartialSession = Omit<Session, "issued" | "expires">;