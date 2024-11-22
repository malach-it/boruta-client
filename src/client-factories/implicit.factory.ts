import { BorutaOauth } from "../boruta-oauth"
import { OauthError, ImplicitSuccess } from "../oauth-responses"
import { STATE_KEY, NONCE_KEY } from '../constants'

export type ImplicitFactoryParams =  {
  oauth: BorutaOauth
  window: Window
}

export type ImplicitParams = {
  clientId: string
  redirectUri: string
  scope?: string
  silentRefresh?: boolean
  silentRefreshCallback?: (response: ImplicitSuccess | OauthError) => void
  responseType?: 'token' | 'id_token token'
}

export type ImplicitExtraParams = {
  prompt: string
}

export class StateError extends Error {
  error: string
  error_description: string

  constructor() {
    super()

    this.error = 'invalid_state'
    this.error_description = 'State does not match with the original given in request.'
  }

  get message() {
    return this.error_description
  }
}

export function createImplicitClient({ oauth, window }: ImplicitFactoryParams) {
  return class Implicit {
    oauth: BorutaOauth
    clientId: string
    responseType: string
    redirectUri: string
    scope: string
    refresh?: ReturnType<typeof setTimeout>
    silentRefreshCallback?: (response: ImplicitSuccess | OauthError) => void

    constructor({ clientId, redirectUri, scope, silentRefresh, silentRefreshCallback, responseType }: ImplicitParams) {
      this.oauth = oauth
      this.clientId = clientId
      this.redirectUri = redirectUri
      this.scope = scope || ''
      this.silentRefreshCallback = silentRefreshCallback
      this.responseType = responseType || 'token'

      if (silentRefresh) {
        window.addEventListener('message', this.handleSilentRefresh.bind(this), false)
      }
    }

    get isOpenid() {
      return this.responseType.match(/id_token/) && this.scope.match(/openid/)
    }

    get state() {
      const current = window.localStorage.getItem(STATE_KEY)
      if (current) return current

      const state = (Math.random() + 1).toString(36).substring(4)
      window.localStorage.setItem(STATE_KEY, state)
      return state
    }

    get nonce() {
      const current = window.localStorage.getItem(NONCE_KEY)
      if (current) return current

      const nonce = (Math.random() + 1).toString(36).substring(4)
      window.localStorage.setItem(NONCE_KEY, nonce)
      return nonce
    }

    get loginUrl(): string {
      return this.buildLoginUrl().toString()
    }

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

        if (id_token) response.id_token = id_token // TODO verify nonce
        if (state) {
          response.state = state
        } else {
          return Promise.reject(new StateError())
        }
        if (state !== this.state) {
          return Promise.reject(new StateError())
        }

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
      return this.parseLocation(window.location).then((response) => {
        if (window.frameElement) {
          window.parent.postMessage(JSON.stringify({
            type: 'boruta_response',
            response
          }), window.location.origin)
        }

        return response
      }).catch(error => {
        if (window.frameElement) {
          window.parent.postMessage(JSON.stringify({
            type: 'boruta_error',
            error
          }), window.location.origin)
        }

        throw error
      })
    }

    silentRefresh(): void {
      const iframe = window.document.createElement('iframe')
      iframe.style.display = 'none'
      iframe.src = this.buildLoginUrl({ prompt: 'none' }).toString()

      window.document.body.appendChild(iframe)
    }

    handleSilentRefresh(message: MessageEvent): void {
      let response
      try {
        const data = JSON.parse(message.data) || {}

        if (data.type === 'boruta_response') {
          response = data.response
        } else if (data.type === 'boruta_error') {
          response = data.error
        } else {
          return
        }
      } catch (error) {
        return
      }

      if (response.expires_in) {
        if (this.refresh) {
          clearTimeout(this.refresh)
        }

        const refresh = setTimeout(() => {
          this.silentRefresh()
        }, response.expires_in * 1000 - 10000)

        this.refresh = refresh
      }

      if (response && this.silentRefreshCallback) {
        this.silentRefreshCallback(response)
      }
    }

    private buildLoginUrl(extraParams: Partial<ImplicitExtraParams> = {}): URL {
      // TODO throw an error in case of misconfiguration (host, authorizePath)
      const url = new URL(oauth.host)
      url.pathname = oauth.authorizePath || ''

      let nonceParam
      if (this.isOpenid) {
        nonceParam = { 'nonce': this.nonce }
      } else {
        nonceParam = {}
      }

      const queryParams = {
        'client_id':  this.clientId,
        'redirect_uri': this.redirectUri,
        'scope': this.scope,
        'response_type': this.responseType,
        'state': this.state,
        ...nonceParam,
        ...extraParams
      }

      Object.entries(queryParams).forEach(([param, value]) => {
        if (!value) return

        url.searchParams.append(
          param,
          <string>value
        )
      })

      return url
    }
  }
}
