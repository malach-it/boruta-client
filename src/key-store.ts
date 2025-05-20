import { SignJWT } from "jose";
import { EbsiWallet } from "@cef-ebsi/wallet-lib"
import { exportJWK, exportPKCS8, importJWK, generateKeyPair, KeyLike, JWK } from "jose"
import { KEY_PAIR_STORAGE_KEY } from './constants'
import { Storage } from './storage'
import { EventHandler } from './event-handler'

export class KeyStore {
  storage: Storage
  eventHandler: EventHandler

  constructor (eventHandler: EventHandler, storage: Storage) {
    this.storage = storage
    this.eventHandler = eventHandler
  }

  async listKeyIdentifiers (): Promise<string[]> {
    const keys = (await this.storage.get<KeyPair[]>(KEY_PAIR_STORAGE_KEY) || [])

    return keys.map(({ identifier }) => identifier)
  }

  async hasKey (identifier: string) {
    return !!(await this.publicKeyJwk(identifier)) && !!(await this.privateKeyJwk(identifier))
  }

  async publicKeyJwk (requestedIdentifier: string): Promise<JWK | null> {
    if (!requestedIdentifier) return null

    const keys = await this.storage.get<KeyPair[]>(KEY_PAIR_STORAGE_KEY)
    return (keys || [])
      .find(({ identifier }) => identifier === requestedIdentifier)
      ?.publicKeyJwk || null
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

    const keys = await this.storage.get<KeyPair[]>(KEY_PAIR_STORAGE_KEY)
    return (keys || [])
      .find(({ identifier }) => identifier === requestedIdentifier)
      ?.privateKeyJwk || null
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

  async storeKeyPair ({ publicKeyJwk, privateKeyJwk, identifier }: KeyPair) {
    const keys = await this.storage.get<KeyPair[]>(KEY_PAIR_STORAGE_KEY) || []
    keys.push({ identifier, publicKeyJwk, privateKeyJwk })
    await this.storage.store(KEY_PAIR_STORAGE_KEY, keys)
  }

  async sign(payload: Object, eventKey: string): Promise<string> {
    const { privateKey, did } = await this.extractKey(eventKey)

    return new SignJWT({
      "iss": did,
      "sub": did,
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
      const handleApproval = (identifier: string) => {
        return doExtractKey(identifier, this).then(resolve).catch(reject)
      }
      this.eventHandler.remove('extract_key-approval', eventKey, handleApproval)
      this.eventHandler.listen('extract_key-approval', eventKey, handleApproval)
    })
  }

  async extractDid(identifier: string): Promise<string> {
    return doExtractDid(identifier, this)
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

async function doExtractKey(identifier: string, keyStore: KeyStore): Promise<{
  identifier: string,
  privateKey: KeyLike,
  publicKey: KeyLike,
  did: string
}> {
  let publicKeyJwk = await keyStore.publicKeyJwk(identifier)
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
      keyStore.eventHandler.listen('generate_key-approval', '', async () => {
        const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true })
        publicKeyJwk = await exportJWK(publicKey)
        const privateKeyJwk = await exportJWK(privateKey)
        await keyStore.storeKeyPair({ identifier, publicKeyJwk, privateKeyJwk })
        return resolve({ privateKey, publicKey })
      })
    })
  }

  if (await keyStore.hasKey(identifier)) {
    publicKey = await keyStore.publicKey(identifier)
    privateKey = await keyStore.privateKey(identifier)
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

async function doExtractDid(identifier: string, keyStore: KeyStore): Promise<string> {
  let publicKeyJwk = await keyStore.publicKeyJwk(identifier)
  let publicKey: KeyLike = { type: 'undefined'}
  let privateKey: KeyLike = { type: 'undefined'}
  let did: string = ''
  let keyFound = false

  async function generateNewKeyPair (): Promise<{
    publicKey: KeyLike
  }> {
    keyStore.eventHandler.dispatch('generate_key-request', identifier)
    return new Promise(resolve => {
      keyStore.eventHandler.listen('generate_key-approval', identifier, async () => {
        const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true })
        publicKeyJwk = await exportJWK(publicKey)
        const privateKeyJwk = await exportJWK(privateKey)
        await keyStore.storeKeyPair({ identifier, publicKeyJwk, privateKeyJwk })
        return resolve({ publicKey })
      })
    })
  }

  if (await keyStore.hasKey(identifier)) {
    publicKey = await keyStore.publicKey(identifier)
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
  const keys = await keyStore.storage.get<KeyPair[]>(KEY_PAIR_STORAGE_KEY) || []

  const keyToRemove = keys.find(({ identifier }) => identifier === requestedIdentifier)

  if (!keyToRemove) return keys.map(({ identifier }) => identifier)

  keys.splice(keys.indexOf(keyToRemove), 1)
  await keyStore.storage.store(KEY_PAIR_STORAGE_KEY, keys)

  return keys.map(({ identifier }) => identifier)
}

type KeyPairParams = {
  publicKeyJwk: JWK
  privateKeyJwk: JWK
  identifier: string
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
