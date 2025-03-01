import { decodeSdJwt } from '@sd-jwt/decode'

import { CredentialSuccess } from './oauth-responses'

const CREDENTIALS_KEY = 'boruta-client_credentials'

export class CredentialsStore {
  window: Window

  constructor (window: Window) {
    this.window = window
  }

  async insertCredential(credentialId: string, credentialResponse: CredentialSuccess): Promise<Array<Credential>> {
    this.window.dispatchEvent(new Event('insert_credential-request~' + credentialId))

    return new Promise((resolve) => {
      this.window.addEventListener('insert_credential-approval~' + credentialId, () => {
        return this.doInsertCredential(credentialId, credentialResponse).then(resolve)
      })
    })
  }

  private async doInsertCredential(credentialId: string, credentialResponse: CredentialSuccess): Promise<Array<Credential>> {
    const credentials = this.credentials

    credentials.push(await Credential.fromResponse(credentialId, credentialResponse))
    this.window.localStorage.setItem(CREDENTIALS_KEY, JSON.stringify(credentials))

    return credentials
  }

  async deleteCredential(credential: string): Promise<Array<Credential>> {
    this.window.dispatchEvent(new Event('delete_credential-request~' + credential))

    return new Promise((resolve) => {
      this.window.addEventListener('delete_credential-approval~' + credential, () => {
        return resolve(this.doDeleteCredential(credential))
      })
    })
  }

  private doDeleteCredential(credential: string): Array<Credential> {
    const credentials = this.credentials

    const toDelete = credentials.find((e: Credential) => {
      return e.credential == credential
    })

    if (!toDelete) return credentials

    credentials.splice(credentials.indexOf(toDelete), 1)
    this.window.localStorage.setItem(CREDENTIALS_KEY, JSON.stringify(credentials))

    return credentials
  }

  get credentials (): Array<Credential> {
    return JSON.parse(
      this.window.localStorage.getItem(CREDENTIALS_KEY) || '[]'
    ).map((credential: CredentialParams) => new Credential(credential))
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
