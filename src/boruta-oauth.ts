import axios from 'axios'
import {
  createPreauthorizedCodeClient,
  createClientCredentialsClient,
  createImplicitClient,
  createRevokeClient,
  createSiopv2Client,
  createVerifiableCredentialsIssuanceClient
} from './client-factories'
import { Storage } from './storage'
import { EventHandler } from './event-handler'

export type BorutaOauthParams = {
  window: Window
  storage?: Storage
  eventHandler?: EventHandler
  host: string
  authorizePath?: string
  tokenPath?: string
  credentialPath?: string
  revokePath?: string
  jwksPath?: string
}

export class BorutaOauth {
  window: Window
  storage?: Storage
  eventHandler?: EventHandler
  host: string
  authorizePath?: string
  tokenPath?: string
  credentialPath?: string
  revokePath?: string
  jwksPath?: string

  constructor ({
    host,
    authorizePath,
    tokenPath,
    credentialPath,
    revokePath,
    jwksPath,
    window,
    storage,
    eventHandler
  }: BorutaOauthParams) {
    this.window = window
    this.storage = storage
    this.eventHandler = eventHandler
    this.host = host
    this.tokenPath = tokenPath
    this.credentialPath = credentialPath
    this.authorizePath = authorizePath
    this.revokePath = revokePath
    this.jwksPath = jwksPath
  }

  get api() {
    return axios.create({
      headers: { 'Content-Type': 'application/json' },
      baseURL: this.host
    })
  }

  get ClientCredentials() {
    return createClientCredentialsClient({ oauth: this })
  }

  get VerifiableCredentialsIssuance() {
    if (!this.storage) {
      throw new Error('You must specify a storage to build this client type.')
    }
    if (!this.eventHandler) {
      throw new Error('You must specify a eventHandler to build this client type.')
    }
    return createVerifiableCredentialsIssuanceClient({ oauth: this, eventHandler: this.eventHandler, storage: this.storage })
  }

  get PreauthorizedCode() {
    if (!this.storage) {
      throw new Error('You must specify a storage to build this client type.')
    }
    return createPreauthorizedCodeClient({ oauth: this, window: this.window, storage: this.storage })
  }

  get Implicit() {
    return createImplicitClient({ oauth: this, window: this.window })
  }

  get Revoke() {
    return createRevokeClient({ oauth: this, window: this.window })
  }

  get Siopv2() {
    if (!this.storage) {
      throw new Error('You must specify a storage to build this client type.')
    }
    if (!this.eventHandler) {
      throw new Error('You must specify a eventHandler to build this client type.')
    }
    return createSiopv2Client({ oauth: this, window: this.window, eventHandler: this.eventHandler, storage: this.storage })
  }
}

