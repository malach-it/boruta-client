import { CompactEncrypt, compactDecrypt, SignJWT } from "jose";
import { EbsiWallet } from "@cef-ebsi/wallet-lib"
import { exportJWK, importJWK, generateKeyPair, KeyLike, JWK } from "jose"
import { KEY_PAIR_STORAGE_KEY } from './constants'
import { Storage } from './storage'
import { EventHandler } from './event-handler'

const JWE_KEY_MANAGEMENT_ALGORITHM = 'PBES2-HS256+A128KW'
const JWE_CONTENT_ENCRYPTION_ALGORITHM = 'A256GCM'
const encoder = new TextEncoder()
const decoder = new TextDecoder()

export class KeyStore {
  storage: Storage
  eventHandler: EventHandler

  constructor (eventHandler: EventHandler, storage: Storage) {
    this.storage = storage
    this.eventHandler = eventHandler
  }

  async listKeyIdentifiers (): Promise<string[]> {
    const keys = await this.storage.get<KeyPair[] | string[]>(KEY_PAIR_STORAGE_KEY) || []

    if (!keys.length) return []

    if (typeof keys[0] == 'string') return keys as string[]

    return (keys as KeyPair[]).map(({ identifier }) => identifier)
  }

  async hasKey (identifier: string) {
    return !!(await this.keyPair(identifier))
  }

  async publicKeyJwk (requestedIdentifier: string): Promise<JWK | null> {
    if (!requestedIdentifier) return null

    return (await this.keyPair(requestedIdentifier))?.publicKeyJwk || null
  }

  async publicKey (identifier: string): Promise<KeyLike> {
    const publicKeyJwk = await this.publicKeyJwk(identifier)

    if (publicKeyJwk) {
      // @ts-ignore
      return importJWK(publicKeyJwk, 'ES256').catch(() => {
        return { type: 'undefined'}
      })
    }
    return Promise.resolve({ type: 'undefined'})
  }

  async privateKeyJwk (requestedIdentifier: string) {
    if (!requestedIdentifier) return null

    return (await this.keyPair(requestedIdentifier))?.privateKeyJwk || null
  }

  async privateKey (identifier: string): Promise<KeyLike> {
    const privateKeyJwk = await this.privateKeyJwk(identifier)

    if (privateKeyJwk) {
      // @ts-ignore
      return importJWK(privateKeyJwk, 'ES256').catch(() => {
        return { type: 'undefined'}
      })
    }
    return Promise.resolve({ type: 'undefined'})
  }

  async keyPair (identifier: string, password?: string): Promise<KeyPairParams | null> {
    const encryptedKeyPair = await this.storage.get<EncryptedKeyPair>(keyPairStorageKey(identifier))

    if (encryptedKeyPair?.jwe) {
      if (!password) {
        throw new Error('Key password approval must provide a password.')
      }

      return decryptKeyPair(encryptedKeyPair.jwe, password)
    }

    const keys = await this.storage.get<KeyPairParams[]>(KEY_PAIR_STORAGE_KEY)
    return (keys || []).find(keyPair => keyPair.identifier === identifier) || null
  }

  async storeKeyPair ({ publicKeyJwk, privateKeyJwk, identifier }: KeyPairParams, password?: string) {
    if (!password) {
      throw new Error('Key password approval must provide a password.')
    }

    const identifiers = await this.listKeyIdentifiers()
    if (!identifiers.includes(identifier)) {
      identifiers.push(identifier)
      await this.storage.store(KEY_PAIR_STORAGE_KEY, identifiers)
    }

    await this.storage.store(
      keyPairStorageKey(identifier),
      await encryptKeyPair({ identifier, publicKeyJwk, privateKeyJwk }, password)
    )
  }

  async sign(payload: Object, eventKey: string): Promise<string> {
    const { privateKey, did } = await this.extractKey(eventKey)

    return new SignJWT({
      "iss": did,
      "sub": did,
      "metadata_policy": {
        client_id: {
          one_of: [ did ]
        }
      },
      ...payload
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'JWT',
        kid: did
      })
      .sign(privateKey)
  }

  async extractKey(eventKey: string): Promise<{
    identifier: string,
    privateKey: KeyLike,
    publicKey: KeyLike,
    did: string
  }> {
    this.eventHandler.dispatch('extract_key-request', eventKey)

    return new Promise((resolve, reject) => {
      const handleApproval = (approval: ExtractKeyApproval) => {
        const { identifier, password } = extractKeyApproval(approval)
        return doExtractKey(identifier, this, password).then(resolve).catch(reject)
      }
      this.eventHandler.remove('extract_key-approval', eventKey, handleApproval)
      this.eventHandler.listen('extract_key-approval', eventKey, handleApproval)
    })
  }

  async extractDid(identifier: string): Promise<string> {
    this.eventHandler.dispatch('extract_key-request', identifier)

    return new Promise((resolve, reject) => {
      const handleApproval = (approval: ExtractKeyApproval) => {
        const { password } = extractKeyApproval(approval, identifier)
        return doExtractDid(identifier, this, password).then(resolve).catch(reject)
      }
      this.eventHandler.remove('extract_key-approval', identifier, handleApproval)
      this.eventHandler.listen('extract_key-approval', identifier, handleApproval)
    })
  }

  async removeKey(identifier: string): Promise<string[]> {
    this.eventHandler.dispatch('remove_key-request', identifier)

    return new Promise((resolve, reject) => {
      const handleApproval = () => {
        return doRemoveKey(identifier, this).then(resolve).catch(reject)
      }
      this.eventHandler.remove('remove_key-approval', identifier, handleApproval)
      this.eventHandler.listen('remove_key-approval', identifier, handleApproval)
    })
  }
}

async function doExtractKey(identifier: string, keyStore: KeyStore, password?: string): Promise<{
  identifier: string,
  privateKey: KeyLike,
  publicKey: KeyLike,
  did: string
}> {
  let keyPair = await keyStore.keyPair(identifier, password)
  let publicKeyJwk = keyPair?.publicKeyJwk
  let publicKey: KeyLike = { type: 'undefined'}
  let privateKey: KeyLike = { type: 'undefined'}
  let did: string = ''
  let keyFound = false

  async function generateNewKeyPair (): Promise<{
    privateKey: KeyLike,
    publicKey: KeyLike
  }> {
    keyStore.eventHandler.dispatch('generate_key-request', '')
    return new Promise(resolve => {
      keyStore.eventHandler.listen('generate_key-approval', '', async (approval: GenerateKeyApproval) => {
        const keyPassword = generateKeyPassword(approval, password)
        const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true })
        publicKeyJwk = await exportJWK(publicKey)
        const privateKeyJwk = await exportJWK(privateKey)
        await keyStore.storeKeyPair({ identifier, publicKeyJwk, privateKeyJwk }, keyPassword)
        return resolve({ privateKey, publicKey })
      })
    })
  }

  if (keyPair) {
    publicKey = await importPublicKey(keyPair.publicKeyJwk)
    privateKey = await importPrivateKey(keyPair.privateKeyJwk)
    keyFound = publicKey.type !== 'undefined' && privateKey.type !== 'undefined'
  }

  if (!keyFound) {
    const { publicKey: newPublicKey, privateKey: newPrivateKey } = await generateNewKeyPair()
    publicKey = newPublicKey
    privateKey = newPrivateKey
    keyFound = publicKey.type !== 'undefined' && privateKey.type !== 'undefined'
  }

  if (!keyFound || !publicKeyJwk) {
    throw new Error('Could not extract key pair.')
  }

  did = EbsiWallet.createDid("NATURAL_PERSON", publicKeyJwk)

  return { identifier, publicKey, privateKey, did }
}

async function doExtractDid(identifier: string, keyStore: KeyStore, password?: string): Promise<string> {
  let keyPair = await keyStore.keyPair(identifier, password)
  let publicKeyJwk = keyPair?.publicKeyJwk
  let publicKey: KeyLike = { type: 'undefined'}
  let keyFound = false

  async function generateNewKeyPair (): Promise<{
    publicKey: KeyLike
  }> {
    keyStore.eventHandler.dispatch('generate_key-request', identifier)
    return new Promise(resolve => {
      keyStore.eventHandler.listen('generate_key-approval', identifier, async (approval: GenerateKeyApproval) => {
        const keyPassword = generateKeyPassword(approval, password)
        const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true })
        publicKeyJwk = await exportJWK(publicKey)
        const privateKeyJwk = await exportJWK(privateKey)
        await keyStore.storeKeyPair({ identifier, publicKeyJwk, privateKeyJwk }, keyPassword)
        return resolve({ publicKey })
      })
    })
  }

  if (keyPair) {
    publicKey = await importPublicKey(keyPair.publicKeyJwk)
    keyFound = publicKey.type !== 'undefined'
  }

  if (!keyFound) {
    const { publicKey: newPublicKey } = await generateNewKeyPair()
    publicKey = newPublicKey
    keyFound = publicKey.type !== 'undefined'
  }

  if (!keyFound || !publicKeyJwk) {
    throw new Error('Could not extract did.')
  }

  return EbsiWallet.createDid("NATURAL_PERSON", publicKeyJwk)
}

async function doRemoveKey (requestedIdentifier: string, keyStore: KeyStore): Promise<string[]> {
  const identifiers = await keyStore.listKeyIdentifiers()

  if (!identifiers.includes(requestedIdentifier)) return identifiers

  identifiers.splice(identifiers.indexOf(requestedIdentifier), 1)
  await keyStore.storage.store(KEY_PAIR_STORAGE_KEY, identifiers)
  await keyStore.storage.store(keyPairStorageKey(requestedIdentifier), null)

  return identifiers
}

type KeyPairParams = {
  publicKeyJwk: JWK
  privateKeyJwk: JWK
  identifier: string
}

type EncryptedKeyPair = {
  jwe: string
}

type ExtractKeyApproval = string | {
  identifier?: string
  password?: string
}

type GenerateKeyApproval = string | {
  password?: string
}

function extractKeyApproval (approval: ExtractKeyApproval, fallbackIdentifier?: string): { identifier: string, password?: string } {
  if (typeof approval == 'string') {
    return { identifier: fallbackIdentifier || approval }
  }

  return {
    identifier: approval.identifier || fallbackIdentifier || '',
    password: approval.password
  }
}

function generateKeyPassword (approval: GenerateKeyApproval, fallbackPassword?: string): string | undefined {
  if (typeof approval == 'string') {
    return fallbackPassword
  }

  return approval.password || fallbackPassword
}

function keyPairStorageKey (identifier: string): string {
  return `${KEY_PAIR_STORAGE_KEY}_${identifier}`
}

async function importPublicKey(publicKeyJwk: JWK): Promise<KeyLike> {
  // @ts-ignore
  return importJWK(publicKeyJwk, 'ES256').catch(() => {
    return { type: 'undefined'}
  })
}

async function importPrivateKey(privateKeyJwk: JWK): Promise<KeyLike> {
  // @ts-ignore
  return importJWK(privateKeyJwk, 'ES256').catch(() => {
    return { type: 'undefined'}
  })
}

async function encryptKeyPair (keyPair: KeyPairParams, password: string): Promise<EncryptedKeyPair> {
  const jwe = await new CompactEncrypt(encoder.encode(JSON.stringify(keyPair)))
    .setProtectedHeader({
      alg: JWE_KEY_MANAGEMENT_ALGORITHM,
      enc: JWE_CONTENT_ENCRYPTION_ALGORITHM
    })
    .encrypt(encoder.encode(password))

  return { jwe }
}

async function decryptKeyPair (jwe: string, password: string): Promise<KeyPairParams> {
  const { plaintext } = await compactDecrypt(jwe, encoder.encode(password), {
    keyManagementAlgorithms: [JWE_KEY_MANAGEMENT_ALGORITHM],
    contentEncryptionAlgorithms: [JWE_CONTENT_ENCRYPTION_ALGORITHM]
  })

  return JSON.parse(decoder.decode(plaintext))
}

class KeyPair {
  publicKeyJwk?: JWK
  privateKeyJwk?: JWK
  publicKey?: KeyLike
  privateKey?: KeyLike
  did?: string
  identifier: string

  constructor ({ publicKeyJwk, privateKeyJwk, identifier }: KeyPairParams) {
    this.publicKeyJwk = publicKeyJwk
    this.privateKeyJwk = privateKeyJwk
    this.identifier = identifier
  }
}
