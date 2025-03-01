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
import { OauthError } from "../oauth-responses";
import { KeyStore, extractKeys } from '../key-store';
export function createVerifiableCredentialsIssuanceClient({ oauth, window }) {
    return class VerifiableCredentialsIssuance {
        constructor({ clientId, clientSecret, redirectUri, scope, grantType }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.redirectUri = redirectUri;
            this.grantType = grantType || 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
            this.scope = scope || '';
            this.keyStore = new KeyStore(window);
        }
        parsePreauthorizedCodeResponse(location) {
            return __awaiter(this, void 0, void 0, function* () {
                if (location.search === '') {
                    return Promise.reject(new OauthError({
                        error: 'unkown_error',
                        error_description: 'Preauthorized code response location must contain query params.'
                    }));
                }
                const params = new URLSearchParams(location.search);
                const { preauthorized_code: preauthorizedCode, credential_issuer: credentialIssuer } = yield parsePreauthorizedCodeParams(params);
                return {
                    preauthorized_code: preauthorizedCode,
                    credential_issuer: credentialIssuer
                };
            });
        }
        getToken(preauthorizedCode) {
            // TODO throw an error in case of misconfiguration (tokenPath)
            const { oauth: { api, tokenPath = '' } } = this;
            const body = {
                grant_type: this.grantType,
                client_id: this.clientId,
                client_secret: this.clientSecret,
                redirect_uri: this.redirectUri,
                'pre-authorized_code': preauthorizedCode,
                scope: this.scope
            };
            return api.post(tokenPath, body).then(({ data }) => {
                return data;
            }).catch(({ status, response }) => {
                throw new OauthError(Object.assign({ status }, response.data));
            });
        }
        getCredential(_a, credentialIdentifier_1, format_1) {
            return __awaiter(this, arguments, void 0, function* ({ access_token: accessToken, }, credentialIdentifier, format) {
                const { oauth: { api, credentialPath = '' } } = this;
                const { privateKey, did } = yield extractKeys(this.keyStore, accessToken);
                const proofJwt = yield new SignJWT({
                    iat: (Date.now() / 1000),
                    aud: this.oauth.host
                })
                    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: did })
                    .sign(privateKey);
                const proof = {
                    proof_type: 'jwt',
                    jwt: proofJwt
                };
                const body = {
                    credential_identifier: credentialIdentifier,
                    format,
                    proof
                };
                return api.post(credentialPath, body, {
                    headers: {
                        'Authorization': `Bearer ${accessToken}`
                    }
                }).then(({ data }) => {
                    return data;
                }).catch(({ status, response }) => {
                    throw new OauthError(Object.assign({ status }, response.data));
                });
            });
        }
    };
}
function parsePreauthorizedCodeParams(params) {
    const credential_offer = params.get('credential_offer');
    if (!credential_offer) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'credential_offer parameter is missing in preauthorized code response location.'
        }));
    }
    const credentialOffer = JSON.parse(decodeURIComponent(credential_offer));
    if (!credentialOffer.credential_issuer) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'credential_offer parameter must contain a credential_issuer attribute.'
        }));
    }
    if (!credentialOffer.grants) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'credential_offer parameter must contain a grants attribute.'
        }));
    }
    if (!credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'credential_offer grants must contain urn:ietf:params:oauth:grant-type:pre-authorized_code attribute.'
        }));
    }
    if (!credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'credential_offer urn:ietf:params:oauth:grant-type:pre-authorized_code must contain a pre-authorized_code attribute.'
        }));
    }
    return Promise.resolve({
        preauthorized_code: credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'],
        credential_issuer: credentialOffer.credential_issuer
    });
}
