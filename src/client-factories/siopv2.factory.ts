import { BorutaOauth } from "../boruta-oauth"
import { OauthError, Siopv2Success } from "../oauth-responses"
import { KeyStore } from '../key-store'
import { STATE_KEY, NONCE_KEY } from '../constants'
import { Storage } from '../storage'
import { EventHandler } from '../event-handler'

export type Siopv2FactoryParams =  {
  oauth: BorutaOauth
  eventHandler: EventHandler
  storage: Storage
}

export type Siopv2Params =  {
  clientId: string
  redirectUri: string
  scope?: string
  responseType?: string
}

export function createSiopv2Client({ oauth, eventHandler, storage }: Siopv2FactoryParams) {
  return class Siopv2 {
    oauth: BorutaOauth
    publicKey?: any
    privateKey?: any
    did?: any
    clientId: string
    redirectUri: string
    scope: string
    responseType: string
    keyStore: KeyStore

    constructor({ clientId, redirectUri, responseType, scope }: Siopv2Params) {
      this.oauth = oauth

      this.clientId = clientId
      this.redirectUri = redirectUri
      this.scope = scope || ''
      this.responseType = responseType || 'code'
      this.keyStore = new KeyStore(eventHandler, storage)
    }

    async parseSiopv2Response(location: Location): Promise<Siopv2Success> {
      if (location.search === '') {
        return Promise.reject(new OauthError({
          error: 'unkown_error',
          error_description: 'Siopv2 response location must contain query params.'
        }))
      }

      const params = new URLSearchParams(location.search)
      const {
        client_id,
        redirect_uri,
        request,
        response_mode,
        response_type,
        scope
      } = await parseSiopv2Params(params)

      if (!oauth.jwksPath) {
        return Promise.reject(new OauthError({
          error: 'unkown_error',
          error_description: 'You must provide server jwks path.'
        }))
      }

      // TODO verify request signature
      // await oauth.api.get<jwksResponse>(oauth.jwksPath).then(({ data }) => {
      //   const keys = data.keys
      //   let jwt
      //   while (keys.length) {
      //     const key = keys.pop()
      //     if (!key) {
      //       throw new OauthError({
      //         error: 'unknown_error',
      //         error_description: 'Request signature could not be verified.'
      //       })
      //     }
      //     console.log(request)
      //     console.log(key)
      //     jwt = verify(request, key, (err, decoded) => console.log(decoded))
      //     console.log(jwt)
      //   }
      // })

      const now = Math.floor((new Date()) as unknown as number / 1000)
      const payload = {
        "aud": redirect_uri,
        "nonce": "nonce",
        "exp": now + 600,
        "iat": now
      }

      const id_token = await this.keyStore.sign(payload, client_id)

      return {
        id_token,
        client_id,
        redirect_uri,
        request,
        response_mode,
        response_type,
        scope
      }
    }

    async state() {
      const current = await storage.get<string>(STATE_KEY)
      if (current) return current

      const state = (Math.random() + 1).toString(36).substring(4)
      await storage.store(STATE_KEY, state)

      return state
    }

    async nonce() {
      const current = await storage.get<string>(NONCE_KEY)
      if (current) return current

      const nonce = (Math.random() + 1).toString(36).substring(4)
      await storage.store(NONCE_KEY, nonce)
      return nonce
    }

    async loginUrl(): Promise<string> {
      const url = await this.buildLoginUrl()
      return url.toString()
    }

    private async buildLoginUrl(): Promise<URL> {
      // TODO throw an error in case of misconfiguration (host, authorizePath)
      const url = new URL(oauth.host)
      url.pathname = oauth.authorizePath || ''

      const queryParams = {
        'client_id':  this.clientId,
        'redirect_uri': this.redirectUri,
        'scope': this.scope,
        'response_type': this.responseType,
        'client_metadata': '{}',
        'state': await this.state(),
        'nonce': this.nonce
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

function parseSiopv2Params(params: URLSearchParams): Promise<Siopv2Success> {
  const client_id = params.get('client_id')
  if (!client_id) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'client_id parameter is missing in Siopv2 response location.'
    }))
  }
  const redirect_uri = params.get('redirect_uri')
  if (!redirect_uri) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'redirect_uri parameter is missing in Siopv2 response location.'
    }))
  }
  const request = params.get('request')
  if (!request) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'request parameter is missing in Siopv2 response location.'
    }))
  }
  const response_mode = params.get('response_mode')
  if (!response_mode) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'response_mode parameter is missing in Siopv2 response location.'
    }))
  }
  const response_type = params.get('response_type')
  if (!response_type) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'response_type parameter is missing in Siopv2 response location.'
    }))
  }
  const scope = params.get('scope') || undefined

  return Promise.resolve({
    id_token: '',
    client_id,
    redirect_uri,
    request,
    response_mode,
    response_type,
    scope
  })
}
