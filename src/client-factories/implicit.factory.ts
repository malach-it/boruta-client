import { BorutaOauth } from "../boruta-oauth"
import { OauthError, ImplicitSuccess } from "../oauth-responses"

export type ImplicitFactoryParams =  {
  oauth: BorutaOauth
  window: Window
}

export type ImplicitParams = {
  clientId: string
  redirectUri: string
  scope?: string
}

export type ImplicitExtraParams = {
  prompt: string
}

export function createImplicitClient({ oauth, window }: ImplicitFactoryParams) {
  return class Implicit {
    oauth: BorutaOauth
    clientId: string
    redirectUri: string
    scope: string

    constructor({ clientId, redirectUri, scope }: ImplicitParams) {
      this.oauth = oauth
      this.clientId = clientId
      this.redirectUri = redirectUri
      this.scope = scope || ''
    }

    get loginUrl(): string {
      return this.buildLoginUrl().toString()
    }

    buildLoginUrl(extraParams: Partial<ImplicitExtraParams> = {}): URL {
      const url = new URL(oauth.host)

      // TODO state & nonce
      const queryParams = {
        'client_id':  this.clientId,
        'redirect_uri': this.redirectUri,
        'scope': this.scope,
        'response_type': 'token',
        ...extraParams
      }

      Object.entries(queryParams).forEach(([param, value]) => {
        if (!value) return

        url.searchParams.append(
          param,
          value
        )
      })

      return url
    }

    // TODO manage oauth error
    parseLocation(location: Location): ImplicitSuccess {
      const hash = location.hash.substring(1)
      const urlSearchParams = new URLSearchParams(hash)

      const access_token = urlSearchParams.get('access_token') || ''
      const id_token = urlSearchParams.get('id_token')
      const expires_in = parseInt(urlSearchParams.get('expires_in') || '0')
      const state = urlSearchParams.get('state')

      const response: ImplicitSuccess = {
        access_token,
        expires_in
      }

      if (id_token) response.id_token = id_token
      if (state) response.state = state

      return response
    }

    silentRefresh(): void {
      const iframe = document.createElement('iframe')
      iframe.style.display = 'none'
      iframe.src = this.buildLoginUrl({ prompt: 'none' }).toString()

      document.body.appendChild(iframe)
    }

    handleIFrameMessage(message: MessageEvent) {
      console.log(message)
    }
  }
}
