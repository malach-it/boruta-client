import axios from 'axios'
import {
  createPreauthorizedCodeClient,
  createClientCredentialsClient,
  createImplicitClient,
  createRevokeClient,
  createSiopv2Client,
  createVerifiableCredentialsIssuanceClient
} from './client-factories'

export type BorutaOauthParams = {
  window: Window
  host: string
  authorizePath?: string
  tokenPath?: string
  credentialPath?: string
  revokePath?: string
  jwksPath?: string
}

export class BorutaOauth {
  window: Window
  host: string
  authorizePath?: string
  tokenPath?: string
  credentialPath?: string
  revokePath?: string
  jwksPath?: string

  constructor ({ host, authorizePath, tokenPath, credentialPath, revokePath, jwksPath, window }: BorutaOauthParams) {
    this.window = window
    this.host = host
    this.tokenPath = tokenPath
    this.credentialPath = credentialPath
    this.authorizePath = authorizePath
    this.revokePath = revokePath
    this.jwksPath = jwksPath
  }

  get api() {
    return axios.create({
      adapter: 'fetch',
      fetchOptions: { mode: 'no-cors' },
      headers: { 'Content-Type': 'application/json' },
      baseURL: this.host
    })
  }

  get ClientCredentials() {
    return createClientCredentialsClient({ oauth: this })
  }

  get VerifiableCredentialsIssuance() {
    return createVerifiableCredentialsIssuanceClient({ oauth: this, window: this.window })
  }

  get PreauthorizedCode() {
    return createPreauthorizedCodeClient({ oauth: this, window: this.window })
  }

  get Implicit() {
    return createImplicitClient({ oauth: this, window: this.window })
  }

  get Revoke() {
    return createRevokeClient({ oauth: this, window: this.window })
  }

  get Siopv2() {
    return createSiopv2Client({ oauth: this, window: this.window })
  }
}
