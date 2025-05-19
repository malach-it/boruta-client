var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { SignJWT } from "jose";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { exportJWK, importJWK, generateKeyPair } from "jose";
import { KEY_PAIR_STORAGE_KEY } from './constants';
export class KeyStore {
    constructor(eventHandler, storage) {
        this.storage = storage;
        this.eventHandler = eventHandler;
    }
    listKeyIdentifiers() {
        return __awaiter(this, void 0, void 0, function* () {
            const keys = ((yield this.storage.get(KEY_PAIR_STORAGE_KEY)) || []);
            return keys.map(({ identifier }) => identifier);
        });
    }
    hasKey(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            return !!(yield this.publicKeyJwk(identifier)) && !!(yield this.privateKeyJwk(identifier));
        });
    }
    publicKeyJwk(requestedIdentifier) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            if (!requestedIdentifier)
                return null;
            const keys = yield this.storage.get(KEY_PAIR_STORAGE_KEY);
            return ((_a = (keys || [])
                .find(({ identifier }) => identifier === requestedIdentifier)) === null || _a === void 0 ? void 0 : _a.publicKeyJwk) || null;
        });
    }
    publicKey(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            const publicKeyJwk = yield this.publicKeyJwk(identifier);
            if (publicKeyJwk) {
                // @ts-ignore
                return importJWK(publicKeyJwk, 'ES256').catch(() => {
                    return { type: 'undefined' };
                });
            }
            return Promise.resolve({ type: 'undefined' });
        });
    }
    privateKeyJwk(requestedIdentifier) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            if (!requestedIdentifier)
                return null;
            const keys = yield this.storage.get(KEY_PAIR_STORAGE_KEY);
            return ((_a = (keys || [])
                .find(({ identifier }) => identifier === requestedIdentifier)) === null || _a === void 0 ? void 0 : _a.privateKeyJwk) || null;
        });
    }
    privateKey(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            const privateKeyJwk = yield this.privateKeyJwk(identifier);
            if (privateKeyJwk) {
                // @ts-ignore
                return importJWK(privateKeyJwk, 'ES256').catch(() => {
                    return { type: 'undefined' };
                });
            }
            return Promise.resolve({ type: 'undefined' });
        });
    }
    storeKeyPair(_a) {
        return __awaiter(this, arguments, void 0, function* ({ publicKeyJwk, privateKeyJwk, identifier }) {
            const keys = (yield this.storage.get(KEY_PAIR_STORAGE_KEY)) || [];
            keys.push({ identifier, publicKeyJwk, privateKeyJwk });
            yield this.storage.store(KEY_PAIR_STORAGE_KEY, keys);
        });
    }
    sign(payload, eventKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const { privateKey, did } = yield this.extractKey(eventKey);
            return new SignJWT(Object.assign({ "iss": did, "sub": did }, payload))
                .setProtectedHeader({
                alg: 'ES256',
                typ: 'JWT',
                kid: did
            })
                .sign(privateKey);
        });
    }
    extractKey(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            this.eventHandler.dispatch('extract_key-request', identifier);
            return new Promise((resolve, reject) => {
                const handleApproval = () => {
                    return doExtractKey(identifier, this).then(resolve).catch(reject);
                };
                this.eventHandler.remove('extract_key-approval', identifier, handleApproval);
                this.eventHandler.listen('extract_key-approval', identifier, handleApproval);
            });
        });
    }
    extractDid(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            return doExtractDid(identifier, this);
        });
    }
    removeKey(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            this.eventHandler.dispatch('remove_key-request', identifier);
            return new Promise((resolve, reject) => {
                const handleApproval = () => {
                    return doRemoveKey(identifier, this).then(resolve).catch(reject);
                };
                this.eventHandler.remove('remove_key-approval', identifier, handleApproval);
                this.eventHandler.listen('remove_key-approval', identifier, handleApproval);
            });
        });
    }
}
function doExtractKey(identifier, keyStore) {
    return __awaiter(this, void 0, void 0, function* () {
        let publicKeyJwk = yield keyStore.publicKeyJwk(identifier);
        let publicKey = { type: 'undefined' };
        let privateKey = { type: 'undefined' };
        let did = '';
        let keyFound = false;
        function generateNewKeyPair() {
            return __awaiter(this, void 0, void 0, function* () {
                keyStore.eventHandler.dispatch('generate_key-request', identifier);
                return new Promise(resolve => {
                    keyStore.eventHandler.listen('generate_key-approval', identifier, () => __awaiter(this, void 0, void 0, function* () {
                        const { privateKey, publicKey } = yield generateKeyPair("ES256", { extractable: true });
                        publicKeyJwk = yield exportJWK(publicKey);
                        const privateKeyJwk = yield exportJWK(privateKey);
                        yield keyStore.storeKeyPair({ identifier, publicKeyJwk, privateKeyJwk });
                        return resolve({ privateKey, publicKey });
                    }));
                });
            });
        }
        if (yield keyStore.hasKey(identifier)) {
            publicKey = yield keyStore.publicKey(identifier);
            privateKey = yield keyStore.privateKey(identifier);
            keyFound = publicKey.type !== 'undefined' && privateKey.type !== 'undefined';
        }
        if (!keyFound) {
            const { publicKey: newPublicKey, privateKey: newPrivateKey } = yield generateNewKeyPair();
            publicKey = newPublicKey;
            privateKey = newPrivateKey;
            keyFound = publicKey.type !== 'undefined' && privateKey.type !== 'undefined';
        }
        if (!keyFound || !publicKeyJwk) {
            throw new Error('Could not extract key pair.');
        }
        did = EbsiWallet.createDid("NATURAL_PERSON", publicKeyJwk);
        return { identifier, publicKey, privateKey, did };
    });
}
function doExtractDid(identifier, keyStore) {
    return __awaiter(this, void 0, void 0, function* () {
        let publicKeyJwk = yield keyStore.publicKeyJwk(identifier);
        let publicKey = { type: 'undefined' };
        let privateKey = { type: 'undefined' };
        let did = '';
        let keyFound = false;
        function generateNewKeyPair() {
            return __awaiter(this, void 0, void 0, function* () {
                keyStore.eventHandler.dispatch('generate_key-request', identifier);
                return new Promise(resolve => {
                    keyStore.eventHandler.listen('generate_key-approval', identifier, () => __awaiter(this, void 0, void 0, function* () {
                        const { privateKey, publicKey } = yield generateKeyPair("ES256", { extractable: true });
                        publicKeyJwk = yield exportJWK(publicKey);
                        const privateKeyJwk = yield exportJWK(privateKey);
                        yield keyStore.storeKeyPair({ identifier, publicKeyJwk, privateKeyJwk });
                        return resolve({ publicKey });
                    }));
                });
            });
        }
        if (yield keyStore.hasKey(identifier)) {
            publicKey = yield keyStore.publicKey(identifier);
            keyFound = publicKey.type !== 'undefined';
        }
        if (!keyFound) {
            const { publicKey: newPublicKey } = yield generateNewKeyPair();
            publicKey = newPublicKey;
            keyFound = publicKey.type !== 'undefined';
        }
        if (!keyFound || !publicKeyJwk) {
            throw new Error('Could not extract did.');
        }
        return EbsiWallet.createDid("NATURAL_PERSON", publicKeyJwk);
    });
}
function doRemoveKey(requestedIdentifier, keyStore) {
    return __awaiter(this, void 0, void 0, function* () {
        const keys = (yield keyStore.storage.get(KEY_PAIR_STORAGE_KEY)) || [];
        const keyToRemove = keys.find(({ identifier }) => identifier === requestedIdentifier);
        if (!keyToRemove)
            return keys.map(({ identifier }) => identifier);
        keys.splice(keys.indexOf(keyToRemove), 1);
        yield keyStore.storage.store(KEY_PAIR_STORAGE_KEY, keys);
        return keys.map(({ identifier }) => identifier);
    });
}
class KeyPair {
    constructor({ publicKeyJwk, privateKeyJwk, identifier }) {
        this.publicKeyJwk = publicKeyJwk;
        this.privateKeyJwk = privateKeyJwk;
        this.identifier = identifier;
    }
}
