"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createImplicitClient = exports.StateError = exports.STATE_KEY = exports.NONCE_KEY = void 0;
const oauth_responses_1 = require("../oauth-responses");
exports.NONCE_KEY = 'boruta_nonce';
exports.STATE_KEY = 'boruta_state';
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
exports.StateError = StateError;
function createImplicitClient({ oauth, window }) {
    return class Implicit {
        constructor({ clientId, redirectUri, scope, silentRefresh, silentRefreshCallback, responseType }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.scope = scope || '';
            this.silentRefreshCallback = silentRefreshCallback;
            this.responseType = responseType || 'token';
            if (silentRefresh) {
                window.addEventListener('message', this.handleSilentRefresh.bind(this), false);
            }
        }
        get isOpenid() {
            return this.responseType == 'id_token token' && this.scope.match(/openid/);
        }
        get state() {
            const current = window.localStorage.getItem(exports.STATE_KEY);
            if (current)
                return current;
            const state = (Math.random() + 1).toString(36).substring(4);
            window.localStorage.setItem(exports.STATE_KEY, state);
            return state;
        }
        get nonce() {
            const current = window.localStorage.getItem(exports.NONCE_KEY);
            if (current)
                return current;
            const nonce = (Math.random() + 1).toString(36).substring(4);
            window.localStorage.setItem(exports.NONCE_KEY, nonce);
            return nonce;
        }
        get loginUrl() {
            return this.buildLoginUrl().toString();
        }
        parseLocation(location) {
            const hash = location.hash.substring(1);
            const urlSearchParams = new URLSearchParams(hash);
            const access_token = urlSearchParams.get('access_token') || '';
            if (access_token) {
                const expires_in = parseInt(urlSearchParams.get('expires_in') || '0');
                const id_token = urlSearchParams.get('id_token');
                const state = urlSearchParams.get('state');
                const response = {
                    access_token,
                    expires_in
                };
                if (id_token)
                    response.id_token = id_token; // TODO verify nonce
                if (state) {
                    response.state = state;
                }
                else {
                    return Promise.reject(new StateError());
                }
                if (state !== this.state) {
                    return Promise.reject(new StateError());
                }
                return Promise.resolve(response);
            }
            const error = urlSearchParams.get('error') || 'unknown_error';
            const error_description = urlSearchParams.get('error_description') || 'Could not be able to parse location.';
            const response = new oauth_responses_1.OauthError({
                error,
                error_description
            });
            return Promise.reject(response);
        }
        callback() {
            return __awaiter(this, void 0, void 0, function* () {
                return this.parseLocation(window.location).then((response) => {
                    if (window.frameElement) {
                        window.parent.postMessage(JSON.stringify({
                            type: 'boruta_response',
                            response
                        }), window.location.origin);
                    }
                    return response;
                }).catch(error => {
                    if (window.frameElement) {
                        window.parent.postMessage(JSON.stringify({
                            type: 'boruta_error',
                            error
                        }), window.location.origin);
                    }
                    throw error;
                });
            });
        }
        silentRefresh() {
            const iframe = window.document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = this.buildLoginUrl({ prompt: 'none' }).toString();
            window.document.body.appendChild(iframe);
        }
        handleSilentRefresh(message) {
            let response;
            try {
                const data = JSON.parse(message.data) || {};
                if (data.type === 'boruta_response') {
                    response = data.response;
                }
                else if (data.type === 'boruta_error') {
                    response = data.error;
                }
                else {
                    return;
                }
            }
            catch (error) {
                return;
            }
            if (response.expires_in) {
                if (this.refresh) {
                    clearTimeout(this.refresh);
                }
                const refresh = setTimeout(() => {
                    this.silentRefresh();
                }, response.expires_in * 1000 - 10000);
                this.refresh = refresh;
            }
            if (response && this.silentRefreshCallback) {
                this.silentRefreshCallback(response);
            }
        }
        buildLoginUrl(extraParams = {}) {
            // TODO throw an error in case of misconfiguration (host, authorizePath)
            const url = new URL(oauth.host);
            url.pathname = oauth.authorizePath || '';
            let nonceParam;
            if (this.isOpenid) {
                nonceParam = { 'nonce': this.nonce };
            }
            else {
                nonceParam = {};
            }
            const queryParams = Object.assign(Object.assign({ 'client_id': this.clientId, 'redirect_uri': this.redirectUri, 'scope': this.scope, 'response_type': this.responseType, 'state': this.state }, nonceParam), extraParams);
            Object.entries(queryParams).forEach(([param, value]) => {
                if (!value)
                    return;
                url.searchParams.append(param, value);
            });
            return url;
        }
    };
}
exports.createImplicitClient = createImplicitClient;
