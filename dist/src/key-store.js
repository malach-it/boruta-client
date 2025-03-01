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
    constructor(window) {
        this.window = window;
    }
    get hasKey() {
        return !!this.publicKeyJwk && !!this.privateKeyJwk;
    }
    get publicKeyJwk() {
        return JSON.parse(this.window.localStorage.getItem(PUBLIC_KEY_STORAGE_KEY) || 'null');
    }
    publicKey() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.publicKeyJwk) {
                // @ts-ignore
                return importJWK(this.publicKeyJwk, 'ES256').catch(() => {
                    return { type: 'undefined' };
                });
            }
            return Promise.resolve({ type: 'undefined' });
        });
    }
    get privateKeyJwk() {
        return JSON.parse(this.window.localStorage.getItem(PRIVATE_KEY_STORAGE_KEY) || 'null');
    }
    privateKey() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.privateKeyJwk) {
                // @ts-ignore
                return importJWK(this.privateKeyJwk, 'ES256').catch(() => {
                    return { type: 'undefined' };
                });
            }
            return Promise.resolve({ type: 'undefined' });
        });
    }
    upsertKeyPair({ publicKeyJwk, privateKeyJwk }) {
        this.window.localStorage.setItem(PUBLIC_KEY_STORAGE_KEY, JSON.stringify(publicKeyJwk));
        this.window.localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, JSON.stringify(privateKeyJwk));
    }
}
export function extractKeys(keyStore, eventKey) {
    return __awaiter(this, void 0, void 0, function* () {
        keyStore.window.dispatchEvent(new Event('extract_key-request~' + eventKey));
        return new Promise((resolve) => {
            keyStore.window.addEventListener('extract_key-approval~' + eventKey, () => {
                return doExtractKeys(keyStore).then(resolve);
            });
        });
    });
}
function doExtractKeys(keyStore) {
    return __awaiter(this, void 0, void 0, function* () {
        let publicKeyJwk;
        let publicKey = { type: 'undefined' };
        let privateKey = { type: 'undefined' };
        let did = '';
        let keyFound = false;
        function generateNewKeyPair() {
            return __awaiter(this, void 0, void 0, function* () {
                const { privateKey, publicKey } = yield generateKeyPair("ES256", { extractable: true });
                publicKeyJwk = yield exportJWK(publicKey);
                const privateKeyJwk = yield exportJWK(privateKey);
                keyStore.upsertKeyPair({ publicKeyJwk, privateKeyJwk });
                return { privateKey, publicKey };
            });
        }
        if (keyStore.hasKey) {
            publicKeyJwk = keyStore.publicKeyJwk;
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
        if (!keyFound) {
            throw new Error('Could not extract key pair.');
        }
        did = EbsiWallet.createDid("NATURAL_PERSON", keyStore.publicKeyJwk);
        return { publicKey, privateKey, did };
    });
}
