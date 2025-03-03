import { SignJWT } from "jose";

import { BorutaOauth } from "../boruta-oauth"
import { OauthError, PreauthorizedCodeSuccess, TokenSuccess, CredentialSuccess } from "../oauth-responses"
import { KeyStore, extractKeys } from '../key-store'
import { CredentialsStore } from '../credentials-store'

export type VerifiableCredentialsIssuanceFactoryParams =  {
  oauth: BorutaOauth
  window: Window
}

export type VerifiableCredentialsIssuanceParams =  {
  clientId: string
  clientSecret?: string
  redirectUri: string
  grantType?: string
  scope?: string
}

export function createVerifiableCredentialsIssuanceClient({ oauth, window }: VerifiableCredentialsIssuanceFactoryParams) {
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
      this.keyStore = new KeyStore(window)
      this.credentialsStore = new CredentialsStore(window)
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

    async getCredentialParams (eventKey: string, credentialIdentifier: string, format: string) {
      const { privateKey, did } = await extractKeys(this.keyStore, eventKey)

      const proofJwt = await new SignJWT({
        iat: (Date.now() / 1000),
        aud: this.oauth.host
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: did })
        .sign(privateKey)

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

    async getCredential ({
      access_token: accessToken,
    }: TokenSuccess, credentialIdentifier: string, format: string) {
      const { oauth: { api, credentialPath = '' } } = this
      const body = await this.getCredentialParams(accessToken, credentialIdentifier, format)

      return api.post<CredentialSuccess>(credentialPath, body, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }).then(({ data }) => {
        return data
      }).catch(({ status, response }) => {
        throw new OauthError({ status, ...response.data })
      }).then(response => {
        return this.credentialsStore.insertCredential(credentialIdentifier, response)
      })
    }
  }
}

function parsePreauthorizedCodeParams(params: URLSearchParams): Promise<PreauthorizedCodeSuccess> {
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
