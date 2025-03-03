var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { exportJWK, importJWK, generateKeyPair } from "jose";
import { PUBLIC_KEY_STORAGE_KEY, PRIVATE_KEY_STORAGE_KEY } from './constants';
export class KeyStore {
    constructor(eventHandler, storage) {
        this.storage = storage;
        this.eventHandler = eventHandler;
    }
    hasKey() {
        return __awaiter(this, void 0, void 0, function* () {
            return !!(yield this.publicKeyJwk()) && !!(yield this.privateKeyJwk());
        });
    }
    publicKeyJwk() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.storage.get(PUBLIC_KEY_STORAGE_KEY);
        });
    }
    publicKey() {
        return __awaiter(this, void 0, void 0, function* () {
            const publicKeyJwk = yield this.publicKeyJwk();
            if (publicKeyJwk) {
                // @ts-ignore
                return importJWK(publicKeyJwk, 'ES256').catch(() => {
                    return { type: 'undefined' };
                });
            }
            return Promise.resolve({ type: 'undefined' });
        });
    }
    privateKeyJwk() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.storage.get(PRIVATE_KEY_STORAGE_KEY);
        });
    }
    privateKey() {
        return __awaiter(this, void 0, void 0, function* () {
            const privateKeyJwk = yield this.privateKeyJwk();
            if (privateKeyJwk) {
                // @ts-ignore
                return importJWK(privateKeyJwk, 'ES256').catch(() => {
                    return { type: 'undefined' };
                });
            }
            return Promise.resolve({ type: 'undefined' });
        });
    }
    upsertKeyPair(_a) {
        return __awaiter(this, arguments, void 0, function* ({ publicKeyJwk, privateKeyJwk }) {
            yield this.storage.store(PUBLIC_KEY_STORAGE_KEY, publicKeyJwk);
            yield this.storage.store(PRIVATE_KEY_STORAGE_KEY, privateKeyJwk);
        });
    }
}
export function extractKeys(keyStore, eventKey) {
    return __awaiter(this, void 0, void 0, function* () {
        keyStore.eventHandler.dispatch('extract_key-request', eventKey);
        return new Promise((resolve, reject) => {
            keyStore.eventHandler.listen('extract_key-approval', eventKey, () => {
                return doExtractKeys(keyStore).then(resolve).catch(reject);
            });
        });
    });
}
function doExtractKeys(keyStore) {
    return __awaiter(this, void 0, void 0, function* () {
        let publicKeyJwk = yield keyStore.publicKeyJwk();
        let publicKey = { type: 'undefined' };
        let privateKey = { type: 'undefined' };
        let did = '';
        let keyFound = false;
        function generateNewKeyPair() {
            return __awaiter(this, void 0, void 0, function* () {
                const { privateKey, publicKey } = yield generateKeyPair("ES256", { extractable: true });
                publicKeyJwk = yield exportJWK(publicKey);
                const privateKeyJwk = yield exportJWK(privateKey);
                yield keyStore.upsertKeyPair({ publicKeyJwk, privateKeyJwk });
                return { privateKey, publicKey };
            });
        }
        if (yield keyStore.hasKey()) {
            publicKey = yield keyStore.publicKey();
            privateKey = yield keyStore.privateKey();
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
        return { publicKey, privateKey, did };
    });
}
