import { SignJWT } from "jose";
import { EbsiWallet } from "@cef-ebsi/wallet-lib"
import { exportJWK, exportPKCS8, importJWK, generateKeyPair, KeyLike, JWK } from "jose"
import { PUBLIC_KEY_STORAGE_KEY, PRIVATE_KEY_STORAGE_KEY } from './constants'
import { Storage } from './storage'
import { EventHandler } from './event-handler'

export type KeyPair = {
  privateKey: KeyLike
  publicKey: KeyLike
  did?: string
}

export class KeyStore {
  storage: Storage
  eventHandler: EventHandler

  constructor (eventHandler: EventHandler, storage: Storage) {
    this.storage = storage
    this.eventHandler = eventHandler
  }

  async hasKey () {
    return !!(await this.publicKeyJwk()) && !!(await this.privateKeyJwk())
  }

  async publicKeyJwk () {
    return this.storage.get<JWK>(PUBLIC_KEY_STORAGE_KEY)
  }

  async publicKey (): Promise<KeyLike> {
    const publicKeyJwk = await this.publicKeyJwk()

    if (publicKeyJwk) {
      // @ts-ignore
      return importJWK(publicKeyJwk, 'ES256').catch(() => {
        return { type: 'undefined'}
      })
    }
    return Promise.resolve({ type: 'undefined'})
  }

  async privateKeyJwk () {
    return this.storage.get<JWK>(PRIVATE_KEY_STORAGE_KEY)
  }

  async privateKey (): Promise<KeyLike> {
    const privateKeyJwk = await this.privateKeyJwk()

    if (privateKeyJwk) {
      // @ts-ignore
      return importJWK(privateKeyJwk, 'ES256').catch(() => {
        return { type: 'undefined'}
      })
    }
    return Promise.resolve({ type: 'undefined'})
  }

  async upsertKeyPair ({ publicKeyJwk, privateKeyJwk }: { publicKeyJwk: JWK, privateKeyJwk: JWK }) {
    await this.storage.store(PUBLIC_KEY_STORAGE_KEY, publicKeyJwk)
    await this.storage.store(PRIVATE_KEY_STORAGE_KEY, privateKeyJwk)
  }

  async sign(payload: Object, eventKey: string): Promise<string> {
    const { privateKey, did } = await this.extractKeys(eventKey)

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

  async extractKeys(eventKey: string): Promise<KeyPair> {
    this.eventHandler.dispatch('extract_key-request', eventKey)

    return new Promise((resolve, reject) => {
      this.eventHandler.listen('extract_key-approval', eventKey, () => {
        return doExtractKeys(this).then(resolve).catch(reject)
      })
    })
  }
}

async function doExtractKeys(keyStore: KeyStore): Promise<{ privateKey: KeyLike, publicKey: KeyLike, did: string }> {
  let publicKeyJwk = await keyStore.publicKeyJwk()
  let publicKey: KeyLike = { type: 'undefined'}
  let privateKey: KeyLike = { type: 'undefined'}
  let did: string = ''
  let keyFound = false

  async function generateNewKeyPair (): Promise<{ privateKey: KeyLike, publicKey: KeyLike }> {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true })
    publicKeyJwk = await exportJWK(publicKey)
    const privateKeyJwk = await exportJWK(privateKey)
    await keyStore.upsertKeyPair({ publicKeyJwk, privateKeyJwk })
    return { privateKey, publicKey }
  }

  if (await keyStore.hasKey()) {
    publicKey = await keyStore.publicKey()
    privateKey = await keyStore.privateKey()
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

  return { publicKey, privateKey, did }
}
