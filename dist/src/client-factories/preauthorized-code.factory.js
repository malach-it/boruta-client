var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { OauthError } from "../oauth-responses";
const STATE_KEY = 'boruta_state';
class StateError extends Error {
    constructor() {
        super();
        this.error = 'invalid_state';
        this.error_description = 'State does not match with the original given in request.';
    }
    get message() {
        return this.error_description;
    }
}
export function createPreauthorizedCodeClient({ oauth, storage }) {
    return class PreauthorizedCode {
        constructor({ clientId, redirectUri, clientSecret, scope }) {
            this.responseType = 'urn:ietf:params:oauth:response-type:pre-authorized_code';
            this.grantType = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
            this.oauth = oauth;
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.clientSecret = clientSecret;
            this.scope = scope || '';
        }
        state() {
            return __awaiter(this, void 0, void 0, function* () {
                const current = storage.get(STATE_KEY);
                if (current)
                    return current;
                const state = (Math.random() + 1).toString(36).substring(4);
                storage.store(STATE_KEY, state);
                return state;
            });
        }
        get loginUrl() {
            return this.buildLoginUrl().toString();
        }
        parseLocation(location) {
            const urlSearchParams = new URLSearchParams(location.search);
            const credentialOffer = urlSearchParams.get('credential_offer') || '';
            if (credentialOffer) {
                this.credentialOffer = JSON.parse(credentialOffer);
                return Promise.resolve(this.credentialOffer);
            }
            const error = urlSearchParams.get('error') || 'unknown_error';
            const error_description = urlSearchParams.get('error_description') || 'Could not be able to parse location.';
            const response = new OauthError({
                error,
                error_description
            });
            return Promise.reject(response);
        }
        buildLoginUrl() {
            return __awaiter(this, arguments, void 0, function* (extraParams = {}) {
                // TODO throw an error in case of misconfiguration (host, authorizePath)
                const url = new URL(oauth.host);
                url.pathname = oauth.authorizePath || '';
                const queryParams = Object.assign({ 'client_id': this.clientId, 'redirect_uri': this.redirectUri, 'scope': this.scope, 'response_type': this.responseType, 'state': yield this.state() }, extraParams);
                Object.entries(queryParams).forEach(([param, value]) => {
                    if (!value)
                        return;
                    url.searchParams.append(param, value);
                });
                return url;
            });
        }
        getToken() {
            if (!this.credentialOffer) {
                return Promise.reject('Must perform a credential offer to get a preauthorized code.');
            }
            const { oauth: { api, tokenPath = '' } } = this;
            const body = {
                grant_type: this.grantType,
                client_id: this.clientId,
                client_secret: this.clientSecret,
                redirect_uri: this.redirectUri,
                'pre-authorized_code': this.credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']
            };
            return api.post(tokenPath, body).then(({ data }) => {
                return data;
            }).catch(({ status, response }) => {
                throw new OauthError(Object.assign({ status }, response.data));
            });
        }
    };
}
