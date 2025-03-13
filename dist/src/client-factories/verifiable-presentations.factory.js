var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { decodeJwt } from "jose";
import { OauthError } from "../oauth-responses";
import { KeyStore } from '../key-store';
import { CredentialsStore } from '../credentials-store';
import { STATE_KEY, NONCE_KEY } from '../constants';
export function createVerifiablePresentationsClient({ oauth, eventHandler, storage }) {
    return class VerifiablePresentations {
        constructor({ clientId, redirectUri, responseType }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.responseType = responseType || 'vp_token';
            this.keyStore = new KeyStore(eventHandler, storage);
            this.credentialsStore = new CredentialsStore(eventHandler, storage);
        }
        parseVerifiablePresentationAuthorization(location) {
            return __awaiter(this, void 0, void 0, function* () {
                if (location.search === '') {
                    return Promise.reject(new OauthError({
                        error: 'unkown_error',
                        error_description: 'VerifiablePresentations response location must contain query params.'
                    }));
                }
                const params = new URLSearchParams(location.search);
                const { request, client_id, redirect_uri, response_mode, response_type, } = yield parseVerifiablePresentationsParams(params);
                const { presentation_definition: { id } } = yield parseVerifiablePresentationRequest(request);
                return {
                    id,
                    request,
                    client_id,
                    redirect_uri,
                    response_mode,
                    response_type,
                };
            });
        }
        generatePresentation(_a) {
            return __awaiter(this, arguments, void 0, function* ({ request, redirect_uri }) {
                const { presentation_definition } = yield parseVerifiablePresentationRequest(request);
                const url = new URL(redirect_uri);
                const presentation = yield this.credentialsStore.presentation(presentation_definition);
                return Object.assign({ redirect_uri }, presentation);
            });
        }
        state() {
            return __awaiter(this, void 0, void 0, function* () {
                const current = yield storage.get(STATE_KEY);
                if (current)
                    return current;
                const state = (Math.random() + 1).toString(36).substring(4);
                yield storage.store(STATE_KEY, state);
                return state;
            });
        }
        nonce() {
            return __awaiter(this, void 0, void 0, function* () {
                const current = yield storage.get(NONCE_KEY);
                if (current)
                    return current;
                const nonce = (Math.random() + 1).toString(36).substring(4);
                yield storage.store(NONCE_KEY, nonce);
                return nonce;
            });
        }
        loginUrl() {
            return __awaiter(this, void 0, void 0, function* () {
                const url = yield this.buildLoginUrl();
                return url.toString();
            });
        }
        buildLoginUrl() {
            return __awaiter(this, void 0, void 0, function* () {
                // TODO throw an error in case of misconfiguration (host, authorizePath)
                const url = new URL(oauth.host);
                url.pathname = oauth.authorizePath || '';
                const queryParams = {
                    'client_id': this.clientId,
                    'redirect_uri': this.redirectUri,
                    'response_type': this.responseType,
                    'client_metadata': '{}',
                    'state': yield this.state(),
                    'nonce': this.nonce
                };
                Object.entries(queryParams).forEach(([param, value]) => {
                    if (!value)
                        return;
                    url.searchParams.append(param, value);
                });
                return url;
            });
        }
    };
}
function parseVerifiablePresentationsParams(params) {
    const request = params.get('request');
    if (!request) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'request parameter is missing in VerifiablePresentations response location.'
        }));
    }
    const client_id = params.get('client_id');
    if (!client_id) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'client_id parameter is missing in VerifiablePresentations response location.'
        }));
    }
    const redirect_uri = params.get('redirect_uri');
    if (!redirect_uri) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'redirect_uri parameter is missing in VerifiablePresentations response location.'
        }));
    }
    const response_mode = params.get('response_mode') || undefined;
    const response_type = params.get('response_type');
    if (!response_type) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'response_type parameter is missing in VerifiablePresentations response location.'
        }));
    }
    return Promise.resolve({
        request,
        client_id,
        redirect_uri,
        response_mode,
        response_type
    });
}
function parseVerifiablePresentationRequest(request) {
    let decodedRequest;
    try {
        decodedRequest = decodeJwt(request);
    }
    catch (error) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: error.toString()
        }));
    }
    const presentation_definition = decodedRequest['presentation_definition'];
    if (!presentation_definition) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'presentation_definition parameter is missing in VerifiablePresentations request.'
        }));
    }
    return Promise.resolve({
        presentation_definition
    });
}
