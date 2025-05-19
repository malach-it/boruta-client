import { BorutaOauth } from "../boruta-oauth"
import { OauthError, PreauthorizedCodeSuccess, TokenSuccess, CredentialSuccess } from "../oauth-responses"
import { KeyStore } from '../key-store'
import { CredentialsStore } from '../credentials-store'
import { Storage } from '../storage'
import { EventHandler } from '../event-handler'

export type VerifiableCredentialsIssuanceFactoryParams =  {
  oauth: BorutaOauth
  eventHandler: EventHandler
  storage: Storage
}

export type VerifiableCredentialsIssuanceParams =  {
  clientId: string
  clientSecret?: string
  redirectUri: string
  grantType?: string
  scope?: string
}

export function createVerifiableCredentialsIssuanceClient({ oauth, eventHandler, storage }: VerifiableCredentialsIssuanceFactoryParams) {
  return class VerifiableCredentialsIssuance {
    oauth: BorutaOauth
    grantType: string
    clientId: string
    clientSecret: string | undefined
    redirectUri: string
    scope: string
    keyStore: KeyStore
    credentialsStore: CredentialsStore

    constructor({ clientId, clientSecret, redirectUri, scope, grantType }: VerifiableCredentialsIssuanceParams) {
      this.oauth = oauth

      this.clientId = clientId
      this.clientSecret = clientSecret
      this.redirectUri = redirectUri
      this.grantType = grantType || 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
      this.scope = scope || ''
      this.keyStore = new KeyStore(eventHandler, storage)
      this.credentialsStore = new CredentialsStore(eventHandler, storage)
    }

    async parsePreauthorizedCodeResponse(location: Location): Promise<PreauthorizedCodeSuccess> {
      if (location.search === '') {
        return Promise.reject(new OauthError({
          error: 'unkown_error',
          error_description: 'Preauthorized code response location must contain query params.'
        }))
      }

      const params = new URLSearchParams(location.search)
      const {
        preauthorized_code: preauthorizedCode,
        credential_issuer: credentialIssuer
      } = await parsePreauthorizedCodeParams(params)

      return {
        preauthorized_code: preauthorizedCode,
        credential_issuer: credentialIssuer
      }
    }

    async getTokenParams (preauthorizedCode: string) {
      return {
        grant_type: this.grantType,
        client_id: this.clientId,
        client_secret: this.clientSecret,
        redirect_uri: this.redirectUri,
        'pre-authorized_code': preauthorizedCode,
        scope: this.scope
      }
    }

    async getToken (preauthorizedCode: string): Promise<TokenSuccess> {
      // TODO throw an error in case of misconfiguration (tokenPath)
      const { oauth: { api, tokenPath = '' } } = this
      const body = await this.getTokenParams(preauthorizedCode)

      return api.post<TokenSuccess>(tokenPath, body).then(({ data }) => {
        return data
      }).catch(({ status, response }) => {
        throw new OauthError({ status, ...response.data })
      })
    }

    async getCredentialParams (keyIdentifier: string, credentialIdentifier: string, format: string) {
      const payload = {
        iat: (Date.now() / 1000),
        aud: this.oauth.host
      }

      const proofJwt = await this.keyStore.sign(payload, keyIdentifier)

      const proof = {
        proof_type: 'jwt',
        jwt: proofJwt
      }

      return {
        credential_identifier: credentialIdentifier,
        format,
        proof
      }
    }

    async getCredential (keyIdentifier: string, {
      access_token: accessToken,
    }: TokenSuccess, credentialIdentifier: string, format: string) {
      const { oauth: { api, credentialPath = '' } } = this
      const body = await this.getCredentialParams(keyIdentifier, credentialIdentifier, format)

      return api.post<CredentialSuccess>(credentialPath, body, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }).then(({ data }) => {
        return data
      }).catch(({ status, response }) => {
        throw new OauthError({ status, ...response.data })
      }).then(async response => {
        await this.credentialsStore.insertCredential(credentialIdentifier, response)
        return response
      })
    }
  }
}

function parsePreauthorizedCodeParams(params: URLSearchParams): Promise<PreauthorizedCodeSuccess> {
  const error = params.get('error')
  if (error) {
    const error_description = params.get('error_description') || ''
    return Promise.reject(new OauthError({
      error,
      error_description
    }))
  }
  const credential_offer = params.get('credential_offer')
  if (!credential_offer) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'credential_offer parameter is missing in preauthorized code response location.'
    }))
  }

  const credentialOffer = JSON.parse(decodeURIComponent(credential_offer))

  if (!credentialOffer.credential_issuer) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'credential_offer parameter must contain a credential_issuer attribute.'
    }))
  }

  if (!credentialOffer.grants) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'credential_offer parameter must contain a grants attribute.'
    }))
  }

  if (!credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'credential_offer grants must contain urn:ietf:params:oauth:grant-type:pre-authorized_code attribute.'
    }))
  }

  if (!credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'credential_offer urn:ietf:params:oauth:grant-type:pre-authorized_code must contain a pre-authorized_code attribute.'
    }))
  }

  return Promise.resolve({
    preauthorized_code: credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'],
    credential_issuer: credentialOffer.credential_issuer
  })

}
