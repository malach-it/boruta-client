var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { decodeSdJwt } from '@sd-jwt/decode';
const CREDENTIALS_KEY = 'boruta-client_credentials';
export class CredentialsStore {
    constructor(window) {
        this.window = window;
    }
    insertCredential(credentialId, credentialResponse) {
        return __awaiter(this, void 0, void 0, function* () {
            this.window.dispatchEvent(new Event('insert_credential-request~' + credentialId));
            return new Promise((resolve) => {
                this.window.addEventListener('insert_credential-approval~' + credentialId, () => {
                    return this.doInsertCredential(credentialId, credentialResponse).then(resolve);
                });
            });
        });
    }
    doInsertCredential(credentialId, credentialResponse) {
        return __awaiter(this, void 0, void 0, function* () {
            const credentials = this.credentials;
            credentials.push(yield Credential.fromResponse(credentialId, credentialResponse));
            this.window.localStorage.setItem(CREDENTIALS_KEY, JSON.stringify(credentials));
            return credentials;
        });
    }
    deleteCredential(credential) {
        return __awaiter(this, void 0, void 0, function* () {
            this.window.dispatchEvent(new Event('delete_credential-request~' + credential));
            return new Promise((resolve) => {
                this.window.addEventListener('delete_credential-approval~' + credential, () => {
                    return resolve(this.doDeleteCredential(credential));
                });
            });
        });
    }
    doDeleteCredential(credential) {
        const credentials = this.credentials;
        const toDelete = credentials.find((e) => {
            return e.credential == credential;
        });
        if (!toDelete)
            return credentials;
        credentials.splice(credentials.indexOf(toDelete), 1);
        this.window.localStorage.setItem(CREDENTIALS_KEY, JSON.stringify(credentials));
        return credentials;
    }
    get credentials() {
        return JSON.parse(this.window.localStorage.getItem(CREDENTIALS_KEY) || '[]').map((credential) => new Credential(credential));
    }
}
export class Credential {
    constructor({ credentialId, format, credential, claims, sub, }) {
        this.credentialId = credentialId;
        this.format = format;
        this.credential = credential;
        this.claims = claims;
        this.sub = sub;
    }
    static fromResponse(credentialId, { format, credential }) {
        return decodeSdJwt(credential, () => { return Promise.resolve(new Uint8Array()); }).then(formattedCredential => {
            const params = {
                credentialId,
                format,
                credential,
                claims: formattedCredential.disclosures.map(({ key, value }) => {
                    return { key, value };
                }),
                sub: formattedCredential.jwt.payload.sub || ''
            };
            return new Credential(params);
        });
    }
}
