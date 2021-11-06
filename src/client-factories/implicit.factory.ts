import { BorutaOauth } from "../boruta-oauth"
import { OauthError, ImplicitSuccess } from "../oauth-responses"

export type ImplicitFactoryParams =  {
  oauth: BorutaOauth
  window: Window
}

export type ImplicitParams = {
  clientId: string
  redirectUri: string
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
