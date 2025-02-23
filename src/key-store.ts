import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { exportJWK, exportPKCS8, importJWK, generateKeyPair, KeyLike, JWK } from "jose";
import { PUBLIC_KEY_STORAGE_KEY, PRIVATE_KEY_STORAGE_KEY } from './constants'

export class KeyStore {
  window: Window

  constructor (window: Window) {
    this.window = window
  }

  get hasKey () {
    return !!this.publicKeyJwk && !!this.privateKeyJwk
  }

  get publicKeyJwk () {
    return JSON.parse(
      this.window.localStorage.getItem(PUBLIC_KEY_STORAGE_KEY) || 'null'
    )
  }

  async publicKey (): Promise<KeyLike> {
    if (this.publicKeyJwk) {
      // @ts-ignore
      return importJWK(this.publicKeyJwk, 'ES256').catch(() => {
        return { type: 'undefined'}
      })
    }
    return Promise.resolve({ type: 'undefined'})
  }

  get privateKeyJwk () {
    return JSON.parse(
      this.window.localStorage.getItem(PRIVATE_KEY_STORAGE_KEY) || 'null'
    )
  }

  async privateKey (): Promise<KeyLike> {
    if (this.privateKeyJwk) {
      // @ts-ignore
      return importJWK(this.privateKeyJwk, 'ES256').catch(() => {
        return { type: 'undefined'}
      })
    }
    return Promise.resolve({ type: 'undefined'})
  }

  upsertKeyPair ({ publicKeyJwk, privateKeyJwk }: { publicKeyJwk: JWK, privateKeyJwk: JWK }) {
    this.window.localStorage.setItem(PUBLIC_KEY_STORAGE_KEY, JSON.stringify(publicKeyJwk))
    this.window.localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, JSON.stringify(privateKeyJwk))
  }
}

export async function extractKeys(keyStore: KeyStore): Promise<{ privateKey: KeyLike, publicKey: KeyLike, did: string }> {
  let publicKeyJwk
  let publicKey: KeyLike = { type: 'undefined'}
  let privateKey: KeyLike = { type: 'undefined'}
  let did: string = ''
  let keyFound = false

  async function generateNewKeyPair (): Promise<{ privateKey: KeyLike, publicKey: KeyLike }> {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true })
    publicKeyJwk = await exportJWK(publicKey)
    const privateKeyJwk = await exportJWK(privateKey)
    keyStore.upsertKeyPair({ publicKeyJwk, privateKeyJwk })
    return { privateKey, publicKey }
  }

  if (keyStore.hasKey) {
    publicKeyJwk = keyStore.publicKeyJwk
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

  if (!keyFound) {
    throw new Error('Could not extract key pair.')
  }

  did = EbsiWallet.createDid("NATURAL_PERSON", keyStore.publicKeyJwk)

  return { publicKey, privateKey, did }
}
