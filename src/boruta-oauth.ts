import axios from 'axios'
import { createPreauthorizedCodeClient, createClientCredentialsClient, createImplicitClient, createRevokeClient } from './client-factories'

export type BorutaOauthParams = {
  window: Window
  host: string
  tokenPath?: string
  authorizePath?: string
  revokePath?: string
}

export class BorutaOauth {
  window: Window
  host: string
  authorizePath?: string
  tokenPath?: string
  revokePath?: string

  constructor ({ host, authorizePath, tokenPath, revokePath, window }: BorutaOauthParams) {
    this.window = window
    this.host = host
    this.tokenPath = tokenPath
    this.authorizePath = authorizePath
    this.revokePath = revokePath
  }

  get api() {
    return axios.create({
      baseURL: this.host
    })
  }

  get ClientCredentials() {
    return createClientCredentialsClient({ oauth: this })
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
}
