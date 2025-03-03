import { decodeSdJwt } from '@sd-jwt/decode'

import { CredentialSuccess } from './oauth-responses'
import { Storage } from './storage'
import { EventHandler } from './event-handler'

const CREDENTIALS_KEY = 'boruta-client_credentials'

export class CredentialsStore {
  eventHandler: EventHandler
  storage: Storage

  constructor (eventHandler: EventHandler, storage: Storage) {
    this.eventHandler = eventHandler
    this.storage = storage
  }

  async insertCredential(credentialId: string, credentialResponse: CredentialSuccess): Promise<Array<Credential>> {
    this.eventHandler.dispatch('insert_credential-request', credentialId)

    return new Promise((resolve, reject) => {
      this.eventHandler.listen('insert_credential-approval', credentialId, () => {
        return this.doInsertCredential(credentialId, credentialResponse).then(resolve).catch(reject)
      })
    })
  }

  private async doInsertCredential(credentialId: string, credentialResponse: CredentialSuccess): Promise<Array<Credential>> {
    const credentials = await this.credentials()

    credentials.push(await Credential.fromResponse(credentialId, credentialResponse))

    await this.storage.store(CREDENTIALS_KEY, credentials)

    return credentials
  }

  async deleteCredential(credential: string): Promise<Array<Credential>> {
    this.eventHandler.dispatch('delete_credential-request', credential)

    return new Promise((resolve, reject) => {
      this.eventHandler.listen('delete_credential-approval', credential, () => {
        return this.doDeleteCredential(credential).then(resolve).catch(reject)
      })
    })
  }

  private async doDeleteCredential(credential: string): Promise<Array<Credential>> {
    const credentials = await this.credentials()

    const toDelete = credentials.find((e: Credential) => {
      return e.credential == credential
    })

    if (!toDelete) return credentials

    credentials.splice(credentials.indexOf(toDelete), 1)
    await this.storage.store(CREDENTIALS_KEY, credentials)

    return credentials
  }

  async credentials (): Promise<Array<Credential>> {
    return this.storage.get<Array<CredentialParams>>(CREDENTIALS_KEY).then(credentials => {
      if (!credentials) return []

      return credentials.map((credential: CredentialParams) => new Credential(credential))
    })
  }
}

type CredentialParams = {
  credentialId: string
  format: string
  credential: string
  claims: Array<{ key: string | undefined, value: unknown }>
  sub: string
}

export class Credential {
  credentialId: string
  format: string
  credential: string
  claims: Array<{ key: string | undefined, value: unknown }>
  sub: string

  constructor({
    credentialId,
    format,
    credential,
    claims,
    sub,
  }: CredentialParams) {
    this.credentialId = credentialId
    this.format = format
    this.credential = credential
    this.claims = claims
    this.sub = sub
  }

  static fromResponse(credentialId: string, { format, credential }: CredentialSuccess): Promise<Credential> {

    return decodeSdJwt(
      credential,
      () => { return Promise.resolve(new Uint8Array()) }
    ).then(formattedCredential => {
      const params = {
        credentialId,
        format,
        credential,
        claims: formattedCredential.disclosures.map(({ key, value }) => {
          return { key, value }
        }),
        sub: formattedCredential.jwt.payload.sub as string || ''
      }
      return new Credential(params)
    })
  }
}
