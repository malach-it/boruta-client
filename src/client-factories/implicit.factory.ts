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
  silentRefresh?: boolean
  silentRefreshCallback?: (response: ImplicitSuccess) => void
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
    private refresh?: number
    silentRefreshCallback?: (response: ImplicitSuccess) => void

    constructor({ clientId, redirectUri, scope, silentRefresh, silentRefreshCallback }: ImplicitParams) {
      this.oauth = oauth
      this.clientId = clientId
      this.redirectUri = redirectUri
      this.scope = scope || ''
      this.silentRefreshCallback = silentRefreshCallback

      if (silentRefresh) {
        window.addEventListener('message', this.handleSilentRefresh.bind(this), false)

        if (!window.frameElement) {
          this.silentRefresh()
        }
      }
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
    parseLocation(location: Location): Promise<ImplicitSuccess> {
      const hash = location.hash.substring(1)
      const urlSearchParams = new URLSearchParams(hash)

      const access_token = urlSearchParams.get('access_token') || ''
      if (access_token) {
        const expires_in = parseInt(urlSearchParams.get('expires_in') || '0')
        const id_token = urlSearchParams.get('id_token')
        const state = urlSearchParams.get('state')

        const response: ImplicitSuccess = {
          access_token,
          expires_in
        }

        if (id_token) response.id_token = id_token
        if (state) response.state = state

        return Promise.resolve(response)
      }

      const error = urlSearchParams.get('error') || 'unknown_error'
      const error_description = urlSearchParams.get('error_description') || 'Could not be able to parse location.'
      const response = new OauthError({
        error,
        error_description
      })

      return Promise.reject(response)
    }

    async callback() {
      const response = await this.parseLocation(window.location)

      if (window.frameElement) {
        // TODO have an environment variable for wildcard and set app host
        window.parent.postMessage(JSON.stringify(response), '*')
      }

      return response
    }

    silentRefresh(): void {
      const iframe = document.createElement('iframe')
      iframe.style.display = 'none'
      iframe.src = this.buildLoginUrl({ prompt: 'none' }).toString()

      document.body.appendChild(iframe)
    }

    handleSilentRefresh(message: MessageEvent): void {
      const response = JSON.parse(message.data) || {}

      if (response.expires_in) {
        if (this.refresh) {
          clearTimeout(this.refresh)
        }

        const refresh = setTimeout(() => {
          this.silentRefresh()
        }, response.expires_in * 1000 - 10000)

        this.refresh = refresh
      }

      if (this.silentRefreshCallback) {
        this.silentRefreshCallback(response)
      }
    }
  }
}
