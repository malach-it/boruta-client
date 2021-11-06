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

export type ImplicitExtraParams = {
  prompt: string
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
      return this.buildLoginUrl().toString()
    }

    buildLoginUrl(extraParams: Partial<ImplicitExtraParams> = {}): URL {
      const url = new URL(oauth.host)

      // TODO state & nonce
      const queryParams = {
        'client_id':  this.clientId,
        'redirect_uri': this.redirectUri,
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

    parseLocation(): ImplicitSuccess {
      const hash = window.location.hash.substring(1)
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

    slientRefresh(): void {
      const iframe = document.createElement('iframe')
      iframe.style.display = 'none'
      iframe.src = this.buildLoginUrl({ prompt: 'none' }).toString()
      iframe.onload = () => {
        const response = this.parseLocation()

        window.parent.postMessage(JSON.stringify(response), "*")
      }

      document.body.appendChild(iframe)
    }

    handleIFrameMessage(message: MessageEvent) {
      console.log(message)
    }
  }
}
