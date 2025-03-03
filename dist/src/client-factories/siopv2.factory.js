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
import { STATE_KEY, NONCE_KEY } from '../constants';
export function createSiopv2Client({ oauth, window, eventHandler, storage }) {
    return class Siopv2 {
        constructor({ clientId, redirectUri, responseType, scope }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.scope = scope || '';
            this.responseType = responseType || 'code';
            this.keyStore = new KeyStore(eventHandler, storage);
        }
        parseSiopv2Response(location) {
            return __awaiter(this, void 0, void 0, function* () {
                if (location.search === '') {
                    return Promise.reject(new OauthError({
                        error: 'unkown_error',
                        error_description: 'Siopv2 response location must contain query params.'
                    }));
                }
                const params = new URLSearchParams(location.search);
                const { client_id, redirect_uri, request, response_mode, response_type, scope } = yield parseSiopv2Params(params);
                if (!oauth.jwksPath) {
                    return Promise.reject(new OauthError({
                        error: 'unkown_error',
                        error_description: 'You must provide server jwks path.'
                    }));
                }
                // TODO verify request signature
                // await oauth.api.get<jwksResponse>(oauth.jwksPath).then(({ data }) => {
                //   const keys = data.keys
                //   let jwt
                //   while (keys.length) {
                //     const key = keys.pop()
                //     if (!key) {
                //       throw new OauthError({
                //         error: 'unknown_error',
                //         error_description: 'Request signature could not be verified.'
                //       })
                //     }
                //     console.log(request)
                //     console.log(key)
                //     jwt = verify(request, key, (err, decoded) => console.log(decoded))
                //     console.log(jwt)
                //   }
                // })
                const { privateKey, did } = yield extractKeys(this.keyStore, client_id);
                const now = Math.floor((new Date()) / 1000);
                const payload = {
                    "iss": did,
                    "sub": did,
                    "aud": redirect_uri,
                    "nonce": "nonce",
                    "exp": now + 600,
                    "iat": now
                };
                const id_token = yield new SignJWT(payload)
                    .setProtectedHeader({ alg: 'ES256', kid: did })
                    .sign(privateKey);
                return {
                    id_token,
                    client_id,
                    redirect_uri,
                    request,
                    response_mode,
                    response_type,
                    scope
                };
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
        get nonce() {
            const current = window.localStorage.getItem(NONCE_KEY);
            if (current)
                return current;
            const nonce = (Math.random() + 1).toString(36).substring(4);
            window.localStorage.setItem(NONCE_KEY, nonce);
            return nonce;
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
                    'scope': this.scope,
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
function parseSiopv2Params(params) {
    const client_id = params.get('client_id');
    if (!client_id) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'client_id parameter is missing in Siopv2 response location.'
        }));
    }
    const redirect_uri = params.get('redirect_uri');
    if (!redirect_uri) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'redirect_uri parameter is missing in Siopv2 response location.'
        }));
    }
    const request = params.get('request');
    if (!request) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'request parameter is missing in Siopv2 response location.'
        }));
    }
    const response_mode = params.get('response_mode');
    if (!response_mode) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'response_mode parameter is missing in Siopv2 response location.'
        }));
    }
    const response_type = params.get('response_type');
    if (!response_type) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'response_type parameter is missing in Siopv2 response location.'
        }));
    }
    const scope = params.get('scope') || undefined;
    return Promise.resolve({
        id_token: '',
        client_id,
        redirect_uri,
        request,
        response_mode,
        response_type,
        scope
    });
}
