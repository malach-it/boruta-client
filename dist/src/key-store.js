var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { CompactEncrypt, compactDecrypt, SignJWT } from "jose";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { exportJWK, importJWK, generateKeyPair } from "jose";
import { KEY_PAIR_STORAGE_KEY } from './constants';
const JWE_KEY_MANAGEMENT_ALGORITHM = 'PBES2-HS256+A128KW';
const JWE_CONTENT_ENCRYPTION_ALGORITHM = 'A256GCM';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
export class KeyStore {
    constructor(eventHandler, storage) {
        this.storage = storage;
        this.eventHandler = eventHandler;
    }
    listKeyIdentifiers() {
        return __awaiter(this, void 0, void 0, function* () {
            const keys = (yield this.storage.get(KEY_PAIR_STORAGE_KEY)) || [];
            if (!keys.length)
                return [];
            if (typeof keys[0] == 'string')
                return keys;
            return keys.map(({ identifier }) => identifier);
        });
    }
    hasKey(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            return !!(yield this.keyPair(identifier));
        });
    }
    publicKeyJwk(requestedIdentifier) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            if (!requestedIdentifier)
                return null;
            return ((_a = (yield this.keyPair(requestedIdentifier))) === null || _a === void 0 ? void 0 : _a.publicKeyJwk) || null;
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
            return ((_a = (yield this.keyPair(requestedIdentifier))) === null || _a === void 0 ? void 0 : _a.privateKeyJwk) || null;
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
    keyPair(identifier, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const encryptedKeyPair = yield this.storage.get(keyPairStorageKey(identifier));
            if (encryptedKeyPair === null || encryptedKeyPair === void 0 ? void 0 : encryptedKeyPair.jwe) {
                if (!password) {
                    throw new Error('Key password approval must provide a password.');
                }
                return decryptKeyPair(encryptedKeyPair.jwe, password);
            }
            const keys = yield this.storage.get(KEY_PAIR_STORAGE_KEY);
            return (keys || []).find(keyPair => keyPair.identifier === identifier) || null;
        });
    }
    storeKeyPair(_a, password_1) {
        return __awaiter(this, arguments, void 0, function* ({ publicKeyJwk, privateKeyJwk, identifier }, password) {
            if (!password) {
                throw new Error('Key password approval must provide a password.');
            }
            const identifiers = yield this.listKeyIdentifiers();
            if (!identifiers.includes(identifier)) {
                identifiers.push(identifier);
                yield this.storage.store(KEY_PAIR_STORAGE_KEY, identifiers);
            }
            yield this.storage.store(keyPairStorageKey(identifier), yield encryptKeyPair({ identifier, publicKeyJwk, privateKeyJwk }, password));
        });
    }
    sign(payload, eventKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const { privateKey, did } = yield this.extractKey(eventKey);
            return new SignJWT(Object.assign({ "iss": did, "sub": did, "metadata_policy": {
                    client_id: {
                        one_of: [did]
                    }
                } }, payload))
                .setProtectedHeader({
                alg: 'ES256',
                typ: 'JWT',
                kid: did
            })
                .sign(privateKey);
        });
    }
    extractKey(eventKey) {
        return __awaiter(this, void 0, void 0, function* () {
            this.eventHandler.dispatch('extract_key-request', eventKey);
            return new Promise((resolve, reject) => {
                const handleApproval = (approval) => {
                    const { identifier, password } = extractKeyApproval(approval);
                    return doExtractKey(identifier, this, password).then(resolve).catch(reject);
                };
                this.eventHandler.remove('extract_key-approval', eventKey, handleApproval);
                this.eventHandler.listen('extract_key-approval', eventKey, handleApproval);
            });
        });
    }
    extractDid(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            this.eventHandler.dispatch('extract_key-request', identifier);
            return new Promise((resolve, reject) => {
                const handleApproval = (approval) => {
                    const { password } = extractKeyApproval(approval, identifier);
                    return doExtractDid(identifier, this, password).then(resolve).catch(reject);
                };
                this.eventHandler.remove('extract_key-approval', identifier, handleApproval);
                this.eventHandler.listen('extract_key-approval', identifier, handleApproval);
            });
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
function doExtractKey(identifier, keyStore, password) {
    return __awaiter(this, void 0, void 0, function* () {
        let keyPair = yield keyStore.keyPair(identifier, password);
        let publicKeyJwk = keyPair === null || keyPair === void 0 ? void 0 : keyPair.publicKeyJwk;
        let publicKey = { type: 'undefined' };
        let privateKey = { type: 'undefined' };
        let did = '';
        let keyFound = false;
        function generateNewKeyPair() {
            return __awaiter(this, void 0, void 0, function* () {
                keyStore.eventHandler.dispatch('generate_key-request', '');
                return new Promise(resolve => {
                    keyStore.eventHandler.listen('generate_key-approval', '', (approval) => __awaiter(this, void 0, void 0, function* () {
                        const keyPassword = generateKeyPassword(approval, password);
                        const { privateKey, publicKey } = yield generateKeyPair("ES256", { extractable: true });
                        publicKeyJwk = yield exportJWK(publicKey);
                        const privateKeyJwk = yield exportJWK(privateKey);
                        yield keyStore.storeKeyPair({ identifier, publicKeyJwk, privateKeyJwk }, keyPassword);
                        return resolve({ privateKey, publicKey });
                    }));
                });
            });
        }
        if (keyPair) {
            publicKey = yield importPublicKey(keyPair.publicKeyJwk);
            privateKey = yield importPrivateKey(keyPair.privateKeyJwk);
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
function doExtractDid(identifier, keyStore, password) {
    return __awaiter(this, void 0, void 0, function* () {
        let keyPair = yield keyStore.keyPair(identifier, password);
        let publicKeyJwk = keyPair === null || keyPair === void 0 ? void 0 : keyPair.publicKeyJwk;
        let publicKey = { type: 'undefined' };
        let keyFound = false;
        function generateNewKeyPair() {
            return __awaiter(this, void 0, void 0, function* () {
                keyStore.eventHandler.dispatch('generate_key-request', identifier);
                return new Promise(resolve => {
                    keyStore.eventHandler.listen('generate_key-approval', identifier, (approval) => __awaiter(this, void 0, void 0, function* () {
                        const keyPassword = generateKeyPassword(approval, password);
                        const { privateKey, publicKey } = yield generateKeyPair("ES256", { extractable: true });
                        publicKeyJwk = yield exportJWK(publicKey);
                        const privateKeyJwk = yield exportJWK(privateKey);
                        yield keyStore.storeKeyPair({ identifier, publicKeyJwk, privateKeyJwk }, keyPassword);
                        return resolve({ publicKey });
                    }));
                });
            });
        }
        if (keyPair) {
            publicKey = yield importPublicKey(keyPair.publicKeyJwk);
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
        const identifiers = yield keyStore.listKeyIdentifiers();
        if (!identifiers.includes(requestedIdentifier))
            return identifiers;
        identifiers.splice(identifiers.indexOf(requestedIdentifier), 1);
        yield keyStore.storage.store(KEY_PAIR_STORAGE_KEY, identifiers);
        yield keyStore.storage.store(keyPairStorageKey(requestedIdentifier), null);
        return identifiers;
    });
}
function extractKeyApproval(approval, fallbackIdentifier) {
    if (typeof approval == 'string') {
        return { identifier: fallbackIdentifier || approval };
    }
    return {
        identifier: approval.identifier || fallbackIdentifier || '',
        password: approval.password
    };
}
function generateKeyPassword(approval, fallbackPassword) {
    if (typeof approval == 'string') {
        return fallbackPassword;
    }
    return approval.password || fallbackPassword;
}
function keyPairStorageKey(identifier) {
    return `${KEY_PAIR_STORAGE_KEY}_${identifier}`;
}
function importPublicKey(publicKeyJwk) {
    return __awaiter(this, void 0, void 0, function* () {
        // @ts-ignore
        return importJWK(publicKeyJwk, 'ES256').catch(() => {
            return { type: 'undefined' };
        });
    });
}
function importPrivateKey(privateKeyJwk) {
    return __awaiter(this, void 0, void 0, function* () {
        // @ts-ignore
        return importJWK(privateKeyJwk, 'ES256').catch(() => {
            return { type: 'undefined' };
        });
    });
}
function encryptKeyPair(keyPair, password) {
    return __awaiter(this, void 0, void 0, function* () {
        const jwe = yield new CompactEncrypt(encoder.encode(JSON.stringify(keyPair)))
            .setProtectedHeader({
            alg: JWE_KEY_MANAGEMENT_ALGORITHM,
            enc: JWE_CONTENT_ENCRYPTION_ALGORITHM
        })
            .encrypt(encoder.encode(password));
        return { jwe };
    });
}
function decryptKeyPair(jwe, password) {
    return __awaiter(this, void 0, void 0, function* () {
        const { plaintext } = yield compactDecrypt(jwe, encoder.encode(password), {
            keyManagementAlgorithms: [JWE_KEY_MANAGEMENT_ALGORITHM],
            contentEncryptionAlgorithms: [JWE_CONTENT_ENCRYPTION_ALGORITHM]
        });
        return JSON.parse(decoder.decode(plaintext));
    });
}
class KeyPair {
    constructor({ publicKeyJwk, privateKeyJwk, identifier }) {
        this.publicKeyJwk = publicKeyJwk;
        this.privateKeyJwk = privateKeyJwk;
        this.identifier = identifier;
    }
}
