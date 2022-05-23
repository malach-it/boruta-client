"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRevokeClient = void 0;
const oauth_responses_1 = require("../oauth-responses");
function createRevokeClient({ oauth, window }) {
    return class Revoke {
        constructor({ clientId, clientSecret }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }
        revoke(token) {
            const { revokePath } = oauth;
            if (!revokePath)
                return Promise.reject();
            const { clientId, clientSecret } = this;
            const data = {
                client_id: this.clientId,
                token: token
            };
            if (clientSecret)
                data['client_secret'] = clientSecret;
            return oauth.api.post(revokePath, data)
                .then(() => { })
                .catch(({ status, response }) => {
                throw new oauth_responses_1.OauthError(Object.assign({ status }, response.data));
            });
        }
    };
}
exports.createRevokeClient = createRevokeClient;
