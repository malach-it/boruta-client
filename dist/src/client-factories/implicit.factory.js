"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createImplicitClient = void 0;
function createImplicitClient({ oauth, window }) {
    return class Implicit {
        constructor({ clientId, redirectUri }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.redirectUri = redirectUri;
        }
        get loginUrl() {
            return this.buildLoginUrl().toString();
        }
        buildLoginUrl(extraParams = {}) {
            const url = new URL(oauth.host);
            // TODO state & nonce
            const queryParams = Object.assign({ 'client_id': this.clientId, 'redirect_uri': this.redirectUri, 'response_type': 'token' }, extraParams);
            Object.entries(queryParams).forEach(([param, value]) => {
                if (!value)
                    return;
                url.searchParams.append(param, value);
            });
            return url;
        }
        // TODO manage oauth error
        parseLocation(location) {
            const hash = location.hash.substring(1);
            const urlSearchParams = new URLSearchParams(hash);
            const access_token = urlSearchParams.get('access_token') || '';
            const id_token = urlSearchParams.get('id_token');
            const expires_in = parseInt(urlSearchParams.get('expires_in') || '0');
            const state = urlSearchParams.get('state');
            const response = {
                access_token,
                expires_in
            };
            if (id_token)
                response.id_token = id_token;
            if (state)
                response.state = state;
            return response;
        }
        silentRefresh() {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = this.buildLoginUrl({ prompt: 'none' }).toString();
            document.body.appendChild(iframe);
        }
        handleIFrameMessage(message) {
            console.log(message);
        }
    };
}
exports.createImplicitClient = createImplicitClient;
