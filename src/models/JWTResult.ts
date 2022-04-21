import { Session } from "./Session";

export interface EncodeResult {
    token: string,
    expires: number,
    issued: number
}

export type DecodeResult = | {
    type: "valid";
    session: Session;
} | {
    type: "integrity-error"
} | {
    type: "invalid-token"
}

export type ExpirationStatus = "expired" | "active" | "grace";