import { BorutaOauth } from "../boruta-oauth"
import { OauthError, PreauthorizedCodeSuccess, TokenSuccess } from "../oauth-responses"
import { Storage } from '../storage'

const STATE_KEY = 'boruta_state'

export type PreauthorizedCodeFactoryParams =  {
  oauth: BorutaOauth
  storage: Storage
  window: Window
}

export type PreauthorizedCodeParams = {
  clientId: string
  redirectUri: string
  clientSecret: string
  scope?: string
}

export type CredentialOffer = {
  grants: {
    'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
      'pre-authorized_code': string
    }
  }
}

export type PreauthorizedCodeExtraParams = {
  prompt: string
}

class StateError extends Error {
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

export function createPreauthorizedCodeClient({ oauth, window, storage }: PreauthorizedCodeFactoryParams) {
  return class PreauthorizedCode {
    oauth: BorutaOauth
    clientId: string
    clientSecret: string
    responseType: string = 'urn:ietf:params:oauth:response-type:pre-authorized_code'
    grantType: string = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
    redirectUri: string
    scope: string
    credentialOffer?: CredentialOffer

    constructor({ clientId, redirectUri, clientSecret, scope }: PreauthorizedCodeParams) {
      this.oauth = oauth
      this.clientId = clientId
      this.redirectUri = redirectUri
      this.clientSecret = clientSecret
      this.scope = scope || ''
    }

    async state() {
      const current = storage.get<string>(STATE_KEY)
      if (current) return current

      const state = (Math.random() + 1).toString(36).substring(4)
      storage.store(STATE_KEY, state)
      return state
    }

    get loginUrl(): string {
      return this.buildLoginUrl().toString()
    }

    parseLocation(location: Location): Promise<CredentialOffer | undefined> {
      const urlSearchParams = new URLSearchParams(window.location.search)

      const credentialOffer = urlSearchParams.get('credential_offer') || ''
      if (credentialOffer) {
        this.credentialOffer = JSON.parse(credentialOffer)
        return Promise.resolve(this.credentialOffer)
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
      return this.parseLocation(window.location)
    }

    async buildLoginUrl(extraParams: Partial<PreauthorizedCodeExtraParams> = {}): Promise<URL> {
      // TODO throw an error in case of misconfiguration (host, authorizePath)
      const url = new URL(oauth.host)
      url.pathname = oauth.authorizePath || ''

      const queryParams = {
        'client_id':  this.clientId,
        'redirect_uri': this.redirectUri,
        'scope': this.scope,
        'response_type': this.responseType,
        'state': await this.state(),
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

    getToken():Promise<TokenSuccess> {
      if (!this.credentialOffer) {
        return Promise.reject('Must perform a credential offer to get a preauthorized code.')
      }
      const { oauth: { api, tokenPath = '' } } = this
      const body = {
        grant_type: this.grantType,
        client_id: this.clientId,
        client_secret: this.clientSecret,
        redirect_uri: this.redirectUri,
        'pre-authorized_code': this.credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']
      }

      return api.post<TokenSuccess>(tokenPath, body).then(({ data }) => {
        return data
      }).catch(({ status, response }) => {
        throw new OauthError({ status, ...response.data })
      })
    }
  }
}
