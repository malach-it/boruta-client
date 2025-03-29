import { OauthError } from "../oauth-responses";
export function createRevokeClient({ oauth }) {
    return class Revoke {
        constructor({ clientId, clientSecret }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }
        revoke(token) {
            const { revokePath } = oauth;
            if (!revokePath)
                return Promise.reject(new Error('revokePath parameter is required.'));
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
                throw new OauthError(Object.assign({ status }, response.data));
            });
        }
    };
}
