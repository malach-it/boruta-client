import { BorutaOauth } from "../boruta-oauth"
import { OauthError, ClientCredentialsSuccess, ImplicitSuccess } from "../oauth-responses"

export type ClientCredentialsFactoryParams =  {
  oauth: BorutaOauth
}

export type ClientCredentialsParams = {
  clientId: string
  clientSecret: string
}

export function createClientCredentialsClient({ oauth }: ClientCredentialsFactoryParams) {
  return class ClientCredentials {
    oauth: BorutaOauth
    clientId: string
    clientSecret: string

    constructor({ clientId, clientSecret }: ClientCredentialsParams) {
      this.oauth = oauth
      this.clientId = clientId
      this.clientSecret = clientSecret
    }

    getToken(): Promise<ClientCredentialsSuccess> {
      // TODO throw an error in case of misconfiguration (tokenPath)
      const { oauth: { api, tokenPath = '' } } = this
      const body = {
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret
      }

      return api.post<ClientCredentialsSuccess>(tokenPath, body).then(({ data }) => {
        return data
      }).catch(({ status, response }) => {
        throw new OauthError({ status, ...response.data })
      })
    }
  }
}
