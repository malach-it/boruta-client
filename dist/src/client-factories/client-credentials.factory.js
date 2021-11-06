"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createClientCredentialsClient = void 0;
const oauth_responses_1 = require("../oauth-responses");
function createClientCredentialsClient({ oauth }) {
    return class ClientCredentials {
        constructor({ clientId, clientSecret }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }
        getToken() {
            const { oauth: { api, tokenPath } } = this;
            const body = {
                grant_type: 'client_credentials',
                client_id: this.clientId,
                client_secret: this.clientSecret
            };
            return api.post(tokenPath, body).then(({ data }) => {
                return data;
            }).catch(({ status, response }) => {
                throw new oauth_responses_1.OauthError(Object.assign({ status }, response.data));
            });
        }
    };
}
exports.createClientCredentialsClient = createClientCredentialsClient;
