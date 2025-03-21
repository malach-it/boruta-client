var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { decodeJwt } from 'jose';
import { decodeSdJwt } from '@sd-jwt/decode';
import { CREDENTIALS_KEY } from './constants';
import { KeyStore } from './key-store';
export class CredentialsStore {
    constructor(eventHandler, storage) {
        this.eventHandler = eventHandler;
        this.storage = storage;
        this.keyStore = new KeyStore(eventHandler, storage);
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
                return Promise.all(credentials.map(({ credentialId, format, credential }) => Credential.fromResponse(credentialId, { format, credential })));
            });
        });
    }
    presentation(_a, credentials_1) {
        return __awaiter(this, arguments, void 0, function* ({ id, input_descriptors }, credentials) {
            if (!credentials) {
                credentials = yield this.credentials();
            }
            const presentationParams = input_descriptors.reduce((acc, descriptor) => {
                let index = 0;
                return credentials.reduce((acc, credential) => {
                    if (credential.validateFormat(Object.keys(descriptor.format))) {
                        return descriptor.constraints.fields.map((field) => {
                            if (credential.hasClaim(field.path[0])) {
                                const descriptor = {
                                    id: credential.credentialId,
                                    path: '$',
                                    format: 'jwt_vp',
                                    path_nested: {
                                        id: index.toString(),
                                        format: credential.format,
                                        path: `$.verifiableCredential[${index}]`
                                    }
                                };
                                index = index + 1;
                                return { credential, descriptor };
                            }
                        })
                            .filter((e) => e)
                            .reduce((acc, current) => {
                            if (!current)
                                return acc;
                            const { credential, descriptor } = current;
                            acc.presentationCredentials.push(credential);
                            acc.descriptorMap.push(descriptor);
                            return acc;
                        }, acc);
                    }
                    else {
                        return acc;
                    }
                }, acc);
            }, { presentationCredentials: [], descriptorMap: [] });
            presentationParams.presentationCredentials = yield Promise.all(presentationParams.presentationCredentials.map(credential => credential.disclosedCredential(input_descriptors)));
            return {
                credentials: presentationParams.presentationCredentials,
                vp_token: yield this.generateVpToken(presentationParams, 'vp_token~' + id),
                presentation_submission: yield this.generatePresentationSubmission(presentationParams, 'presentation_submission~' + id)
            };
        });
    }
    generateVpToken(_a, eventKey_1) {
        return __awaiter(this, arguments, void 0, function* ({ presentationCredentials }, eventKey) {
            const payload = {
                'id': eventKey,
                '@context': [
                    'https://www.w3.org/2018/credentials/v1'
                ],
                'type': [
                    'VerifiablePresentation'
                ],
                'verifiableCredential': presentationCredentials.map(({ credential }) => credential)
            };
            return this.keyStore.sign(payload, eventKey);
        });
    }
    generatePresentationSubmission(_a, eventKey_1) {
        return __awaiter(this, arguments, void 0, function* ({ descriptorMap }, eventKey) {
            return JSON.stringify({
                id: eventKey,
                descriptor_map: descriptorMap
            });
        });
    }
}
export class Credential {
    constructor({ credentialId, format, credential, claims, disclosures, sub, }) {
        this.credentialId = credentialId;
        this.format = format;
        this.credential = credential;
        this.claims = claims;
        this.disclosures = disclosures;
        this.sub = sub;
    }
    hasClaim(path) {
        const claims = this.claims;
        const pathInfo = path.replace(/^$/, '').split('.');
        const current = pathInfo.pop();
        const claim = claims.find(({ key }) => key == current);
        return !!claim;
    }
    validateFormat(formats) {
        return formats.includes(this.format);
    }
    static fromResponse(credentialId_1, _a) {
        return __awaiter(this, arguments, void 0, function* (credentialId, { format, credential }) {
            if (format == 'vc+sd-jwt') {
                return decodeSdJwt(credential, () => { return Promise.resolve(new Uint8Array()); }).then(formattedCredential => {
                    const params = {
                        credentialId,
                        format,
                        credential,
                        disclosures: formattedCredential.disclosures.map(disclosure => {
                            return {
                                key: disclosure.key || '',
                                value: disclosure.value,
                                // @ts-ignore
                                encoded: disclosure._encoded
                            };
                        }),
                        claims: formattedCredential.disclosures.map(({ key, value }) => {
                            return { key, value: value || '' };
                        }),
                        sub: formattedCredential.jwt.payload.sub || ''
                    };
                    return new Credential(params);
                });
            }
            if (format == 'jwt_vc') {
                const claims = yield decodeJwt(credential);
                const credentialId = Object.keys(claims.credentialSubject)[0];
                const params = {
                    credentialId,
                    format,
                    credential,
                    disclosures: [],
                    claims: Object.keys(claims.credentialSubject[credentialId]).map(key => {
                        const value = claims.credentialSubject[credentialId][key];
                        return { key, value };
                    }),
                    sub: claims.credentialSubject[credentialId].id
                };
                return new Credential(params);
            }
            return Promise.reject(new Error('Unsupported format.'));
        });
    }
    disclosedCredential(inputDescriptors) {
        return __awaiter(this, void 0, void 0, function* () {
            const credential = yield Credential.fromResponse(this.credentialId, this);
            const disclosures = credential.disclosures.filter(disclosure => {
                return !inputDescriptors.some(descriptor => {
                    return descriptor['constraints']['fields'].some(field => {
                        return field['path'].some(path => {
                            return path.replace(/^\$\./, '') == disclosure.key;
                        });
                    });
                });
            });
            credential.claims = credential.claims.filter(claim => {
                return !disclosures.map(({ key }) => key).includes(claim.key || '');
            });
            credential.disclosures = credential.disclosures.filter(disclosure => {
                return !disclosures.map(({ key }) => key).includes(disclosure.key);
            });
            disclosures.forEach(disclosure => {
                credential.credential = credential.credential.replace(disclosure.encoded + '~', '');
            });
            return credential;
        });
    }
}
