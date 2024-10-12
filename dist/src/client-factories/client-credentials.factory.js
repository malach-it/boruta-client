import { OauthError } from "../oauth-responses";
export function createClientCredentialsClient({ oauth }) {
    return class ClientCredentials {
        constructor({ clientId, clientSecret }) {
            this.oauth = oauth;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }
        getToken() {
            // TODO throw an error in case of misconfiguration (tokenPath)
            const { oauth: { api, tokenPath = '' } } = this;
            const body = {
                grant_type: 'client_credentials',
                client_id: this.clientId,
                client_secret: this.clientSecret
            };
            return api.post(tokenPath, body).then(({ data }) => {
                return data;
            }).catch(({ status, response }) => {
                throw new OauthError(Object.assign({ status }, response.data));
            });
        }
    };
}
