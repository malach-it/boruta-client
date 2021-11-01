import { BorutaOauth } from "./boruta-oauth"
import { OauthError, ClientCredentialsSuccess, ImplicitSuccess } from "./oauth-responses"

export type ClientCredentialsFactoryParams =  {
  oauth: BorutaOauth
}

export type ImplicitFactoryParams =  {
  oauth: BorutaOauth
  window: Window
}

export type ClientCredentialsParams = {
  clientId: string
  clientSecret: string
}

export type ImplicitParams = {
  clientId: string
  redirectUri: string
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
      const { oauth: { api, tokenPath } } = this
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

export function createImplicitClient({ oauth, window }: ImplicitFactoryParams) {
  return class Implicit {
    oauth: BorutaOauth
    clientId: string
    redirectUri: string

    constructor({ clientId, redirectUri }: ImplicitParams) {
      this.oauth = oauth
      this.clientId = clientId
      this.redirectUri = redirectUri
    }

    get loginUrl(): string {
      const url = new URL(oauth.host)
      url.searchParams.append('client_id',  this.clientId)
      url.searchParams.append('redirect_uri', this.redirectUri)
      url.searchParams.append('response_type', 'token')

      return url.toString()
    }

    parseLocation(): ImplicitSuccess {
      const hash = window.location.hash.substring(1)
      const urlSearchParams = new URLSearchParams(hash)

      const access_token = urlSearchParams.get('access_token') || ''
      const id_token = urlSearchParams.get('id_token') || undefined
      const expires_in = parseInt(urlSearchParams.get('expires_in') || '0')
      const state = urlSearchParams.get('state') || undefined

      const result: ImplicitSuccess = {
        access_token,
        expires_in
      }

      if (id_token) result.id_token = id_token
      if (state) result.state = state

      return result
    }
  }
}
