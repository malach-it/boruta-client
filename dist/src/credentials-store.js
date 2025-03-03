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
    constructor(eventHandler, storage) {
        this.eventHandler = eventHandler;
        this.storage = storage;
    }
    insertCredential(credentialId, credentialResponse) {
        return __awaiter(this, void 0, void 0, function* () {
            this.eventHandler.dispatch('insert_credential-request', credentialId);
            return new Promise((resolve, reject) => {
                this.eventHandler.listen('insert_credential-approval', credentialId, () => {
                    return this.doInsertCredential(credentialId, credentialResponse).then(resolve).catch(reject);
                });
            });
        });
    }
    doInsertCredential(credentialId, credentialResponse) {
        return __awaiter(this, void 0, void 0, function* () {
            const credentials = yield this.credentials();
            credentials.push(yield Credential.fromResponse(credentialId, credentialResponse));
            yield this.storage.store(CREDENTIALS_KEY, credentials);
            return credentials;
        });
    }
    deleteCredential(credential) {
        return __awaiter(this, void 0, void 0, function* () {
            this.eventHandler.dispatch('delete_credential-request', credential);
            return new Promise((resolve, reject) => {
                this.eventHandler.listen('delete_credential-approval', credential, () => {
                    return this.doDeleteCredential(credential).then(resolve).catch(reject);
                });
            });
        });
    }
    doDeleteCredential(credential) {
        return __awaiter(this, void 0, void 0, function* () {
            const credentials = yield this.credentials();
            const toDelete = credentials.find((e) => {
                return e.credential == credential;
            });
            if (!toDelete)
                return credentials;
            credentials.splice(credentials.indexOf(toDelete), 1);
            yield this.storage.store(CREDENTIALS_KEY, credentials);
            return credentials;
        });
    }
    credentials() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.storage.get(CREDENTIALS_KEY).then(credentials => {
                if (!credentials)
                    return [];
                return credentials.map((credential) => new Credential(credential));
            });
        });
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
