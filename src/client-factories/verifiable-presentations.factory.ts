import { SignJWT, decodeJwt } from "jose";
import { BorutaOauth } from "../boruta-oauth"
import { OauthError, PresentationDefinition, VerifiablePresentationSuccess } from "../oauth-responses"
import { KeyStore } from '../key-store'
import { Credential, CredentialsStore, PresentationCredentials } from '../credentials-store'
import { STATE_KEY, NONCE_KEY } from '../constants'
import { Storage } from '../storage'
import { EventHandler } from '../event-handler'

export type VerifiablePresentationsFactoryParams =  {
  oauth: BorutaOauth
  eventHandler: EventHandler
  storage: Storage
}

export type VerifiablePresentationsParams =  {
  clientId: string
  redirectUri: string
  responseType?: string
}

export type VerifiablePresentationResult = VerifiablePresentationSuccess & {
  id: string
}

type PresentationResult = PresentationCredentials & {
  redirect_uri: string
}

export function createVerifiablePresentationsClient({ oauth, eventHandler, storage }: VerifiablePresentationsFactoryParams) {
  return class VerifiablePresentations {
    oauth: BorutaOauth
    publicKey?: any
    privateKey?: any
    did?: any
    clientId: string
    redirectUri: string
    responseType: string
    keyStore: KeyStore
    credentialsStore: CredentialsStore

    constructor({ clientId, redirectUri, responseType }: VerifiablePresentationsParams) {
      this.oauth = oauth

      this.clientId = clientId
      this.redirectUri = redirectUri
      this.responseType = responseType || 'vp_token'
      this.keyStore = new KeyStore(eventHandler, storage)
      this.credentialsStore = new CredentialsStore(eventHandler, storage)
    }

    async parseVerifiablePresentationAuthorization(location: Location): Promise<VerifiablePresentationResult> {
      if (location.search === '') {
        return Promise.reject(new OauthError({
          error: 'unkown_error',
          error_description: 'VerifiablePresentations response location must contain query params.'
        }))
      }

      const params = new URLSearchParams(location.search)
      const parsedPresentation = await parseVerifiablePresentationsParams(params)

      if (!parsedPresentation) {
        return Promise.reject(new OauthError({
          error: 'unkown_error',
          error_description: 'Presentation success.'
        }))
      }

      const {
        request,
        presentation_definition,
        client_id,
        redirect_uri,
        response_mode,
        response_type,
      } = parsedPresentation

      return {
        id: presentation_definition.id,
        presentation_definition,
        request,
        client_id,
        redirect_uri,
        response_mode,
        response_type,
      }
    }

    async generatePresentation({
      request,
      redirect_uri
    }: VerifiablePresentationSuccess,
    credentials?: Array<Credential>): Promise<PresentationResult> {
      const url = new URL(redirect_uri)

      const { presentation_definition } = await parseVerifiablePresentationRequest(request)

      const presentation = await this.credentialsStore.presentation(presentation_definition, credentials)

      return {
        redirect_uri,
        ...presentation
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

async function parseVerifiablePresentationsParams(params: URLSearchParams): Promise<VerifiablePresentationSuccess | void> {
  const error = params.get('error')
  if (error) {
    const error_description = params.get('error_description') || ''
    return Promise.reject(new OauthError({
      error,
      error_description
    }))
  }

  const code = params.get('code')
  if (code) {
    return Promise.resolve()
  }

  const request = params.get('request')
  if (!request) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'request parameter is missing in VerifiablePresentations response location.'
    }))
  }
  const { presentation_definition } = await parseVerifiablePresentationRequest(request)

  const client_id = params.get('client_id')
  if (!client_id) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'client_id parameter is missing in VerifiablePresentations response location.'
    }))
  }

  const redirect_uri = params.get('redirect_uri')
  if (!redirect_uri) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'redirect_uri parameter is missing in VerifiablePresentations response location.'
    }))
  }

  const response_mode = params.get('response_mode') || undefined

  const response_type = params.get('response_type')
  if (!response_type) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'response_type parameter is missing in VerifiablePresentations response location.'
    }))
  }

  return Promise.resolve({
    request,
    presentation_definition,
    client_id,
    redirect_uri,
    response_mode,
    response_type
  })
}

function parseVerifiablePresentationRequest(request: string): Promise<{ presentation_definition: PresentationDefinition }> {
  let decodedRequest
  try {
    decodedRequest = decodeJwt(request)
  } catch (error) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: (error as Error).toString()
    }))
  }

  const presentation_definition = decodedRequest['presentation_definition']
  if (!presentation_definition) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'presentation_definition parameter is missing in VerifiablePresentations request.'
    }))
  }

  return Promise.resolve({
    presentation_definition
  })
}
