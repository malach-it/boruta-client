import axios from 'axios'
import { createClientCredentialsClient, createImplicitClient } from './client-factories'

export type BorutaOauthParams = {
  window: Window
  host: string
  tokenPath?: string
  authorizePath?: string
}

export class BorutaOauth {
  window: Window
  host: string
  authorizePath?: string
  tokenPath?: string

  constructor ({ host, authorizePath, tokenPath, window }: BorutaOauthParams) {
    this.window = window
    this.host = host
    this.tokenPath = tokenPath
    this.authorizePath = authorizePath
  }

  get api() {
    return axios.create({
      baseURL: this.host
    })
  }

  get ClientCredentials() {
    return createClientCredentialsClient({ oauth: this })
  }

  get Implicit() {
    return createImplicitClient({ oauth: this, window: this.window })
  }
}
