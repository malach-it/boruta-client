import { decodeJwt } from 'jose'
import { decodeSdJwt } from '@sd-jwt/decode'

import { CredentialSuccess, PresentationDefinition, InputDescriptor } from './oauth-responses'
import { Storage } from './storage'
import { EventHandler } from './event-handler'
import { CREDENTIALS_KEY } from './constants'
import { KeyStore } from './key-store'

export type PresentationCredentials = {
  credentials: Array<Credential>
  vp_token: string
  presentation_submission: string
}

type Descriptor = {
  id: string,
  format: string
  path: string,
  path_nested: {
    format: string
    path: string
  }
}

type PresentationParams = {
  presentationCredentials: Array<Credential>
  descriptorMap: Array<Descriptor>
}

export class CredentialsStore {
  eventHandler: EventHandler
  keyStore: KeyStore
  storage: Storage

  constructor (eventHandler: EventHandler, storage: Storage) {
    this.eventHandler = eventHandler
    this.storage = storage
    this.keyStore = new KeyStore(eventHandler, storage)
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

      return Promise.all(
        credentials.map(({ credentialId, format, credential }: CredentialParams) => Credential.fromResponse(credentialId, { format, credential }))
      )
    })
  }

  async presentation({ id, input_descriptors }: PresentationDefinition): Promise<PresentationCredentials> {
    const credentials = await this.credentials()

    const presentationParams = input_descriptors.reduce((acc: PresentationParams, descriptor: InputDescriptor) => {
      let index = 0

      return credentials.reduce((acc: PresentationParams, credential: Credential) => {
        if (credential.validateFormat(Object.keys(descriptor.format))) {
          return descriptor.constraints.fields.map((field: { path: string }) => {
            if (
              credential.hasClaim(field.path[0])
            ) {
              const descriptor = {
                id: credential.credentialId,
                path: '$',
                format: credential.format,
                path_nested: {
                  format: credential.format,
                  path: `$.verifiableCredential[${index}]`
                }
              }
              index = index + 1
              return { credential, descriptor }
            }
          })
            .filter((e: { credential: Credential, descriptor: Descriptor } | undefined) => e)
            .reduce((
              acc: PresentationParams,
              current: { credential: Credential, descriptor: Descriptor } | undefined
            ) => {
              if (!current) return acc
              const { credential, descriptor } = current

              acc.presentationCredentials.push(credential)
              acc.descriptorMap.push(descriptor)
              return acc
            }, acc)
        } else {
          return acc
        }
      }, acc)
    }, { presentationCredentials: [], descriptorMap: [] })

    return {
      credentials: presentationParams.presentationCredentials,
      vp_token: await this.generateVpToken(presentationParams, 'vp_token~' + id),
      presentation_submission: await this.generatePresentationSubmission(presentationParams, 'presentation_submission~' + id)
    }
  }

  async generateVpToken({ presentationCredentials }: PresentationParams, eventKey: string): Promise<string> {
    const payload = {
      'id': eventKey,
      '@context': [
        'https://www.w3.org/2018/credentials/v1'
      ],
      'type': [
        'VerifiablePresentation'
      ],
      'verifiableCredential': presentationCredentials.map(({ credential }) => credential)
    }
    return this.keyStore.sign(payload, eventKey)
  }

  async generatePresentationSubmission({ descriptorMap }: PresentationParams, eventKey: string): Promise<string> {
    return JSON.stringify({
      id: eventKey,
      descriptor_map: descriptorMap
    })
  }
}

type CredentialParams = {
  credentialId: string
  format: string
  credential: string
  claims: Array<{ key: string | undefined, value: string | Object }>
  sub: string
}

type CredentialClaim = { key: string | undefined, value: string | Object }

export class Credential {
  credentialId: string
  format: string
  credential: string
  claims: Array<CredentialClaim>
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

  hasClaim (path: string): boolean {
    const claims = this.claims
    const pathInfo = path.replace(/^$/, '').split('.')

    const current = pathInfo.pop()
    const claim = claims.find(({ key }) => key == current)
    return !!claim
  }

  validateFormat (formats: Array<string>): boolean {
    return formats.includes(this.format)
  }

  static async fromResponse(credentialId: string, { format, credential }: CredentialSuccess): Promise<Credential> {

    if (format == 'vc+sd-jwt') {
      return decodeSdJwt(
        credential,
        () => { return Promise.resolve(new Uint8Array()) }
      ).then(formattedCredential => {
        const params = {
          credentialId,
          format,
          credential,
          claims: formattedCredential.disclosures.map(({ key, value }) => {
            return { key, value: value as string || '' }
          }),
          sub: formattedCredential.jwt.payload.sub as string || ''
        }
        return new Credential(params)
      })
    }
    if (format == 'jwt_vc') {
      const claims: JwtVcCredential = await decodeJwt(credential)
      const credentialId = Object.keys(claims.credentialSubject)[0]
      const params = {
        credentialId,
        format,
        credential,
        claims: Object.keys(claims.credentialSubject[credentialId]).map(key => {
          const value: string | Object = claims.credentialSubject[credentialId][key]
          return { key, value }
        }),
        sub: claims.credentialSubject[credentialId].id
      }
      return new Credential(params)
    }

    return Promise.reject(new Error('Unsupported format.'))
  }
}

type JwtVcCredential = {
  credentialSubject: {
    [key: string]: {
      [key: Exclude<string, 'id'>]: string | Object
      id: string
    }
  }
  id: string
}
