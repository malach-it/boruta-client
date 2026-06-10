import "mocha"
import chai from 'chai'
const { expect } = chai
import chaiAsPromised from 'chai-as-promised'
import { KeyStore } from '../../src/key-store'
import { EventHandler, StoreEventType } from '../../src/event-handler'
import { Storage } from '../../src/storage'
import { KEY_PAIR_STORAGE_KEY } from '../../src/constants'

chai.use(chaiAsPromised)

class MemoryStorage implements Storage {
  values: { [key: string]: unknown } = {}

  async store (key: string, value: unknown): Promise<void> {
    this.values[key] = value
  }

  async get<T> (key: string): Promise<T | null> {
    return this.values[key] as T || null
  }
}

class KeyEventHandler implements EventHandler {
  identifier: string
  password: string
  dispatched: Array<{ type: StoreEventType, key: string | undefined }> = []

  constructor (identifier: string, password: string) {
    this.identifier = identifier
    this.password = password
  }

  async dispatch(type: StoreEventType, key?: string): Promise<void> {
    this.dispatched.push({ type, key })
  }

  async listen(type: StoreEventType, key: string, callback: Function): Promise<void> {
    if (type == 'extract_key-approval') {
      callback({ identifier: this.identifier, password: this.password })
      return
    }
    if (type == 'generate_key-approval') {
      callback({ password: this.password })
      return
    }

    callback(key)
  }

  async remove(type: StoreEventType, key: string, callback: Function): Promise<void> {}
}

describe('KeyStore', () => {
  describe('#extractKey', () => {
    it('stores key pairs as password-protected JWE entries under the prefixed identifier key', async () => {
      const storage = new MemoryStorage()
      const eventHandler = new KeyEventHandler('test-key', 'password')
      const keyStore = new KeyStore(eventHandler, storage)

      await keyStore.extractKey('credential')

      const identifiers = await storage.get<string[]>(KEY_PAIR_STORAGE_KEY)
      const storedKeyPair = await storage.get<{ jwe: string }>(`${KEY_PAIR_STORAGE_KEY}_test-key`)

      expect(eventHandler.dispatched.map(({ type }) => type)).to.include.members([
        'extract_key-request',
        'generate_key-request'
      ])
      expect(identifiers).to.deep.eq(['test-key'])
      expect(storedKeyPair?.jwe).to.be.a('string')
      expect(storedKeyPair).not.to.have.property('privateKeyJwk')
    })

    it('uses the generate key approval password when creating a new encrypted key pair', async () => {
      const storage = new MemoryStorage()
      const eventHandler = new KeyEventHandler('test-key', 'extract-password')
      const keyStore = new KeyStore(eventHandler, storage)
      let extractPassword = 'extract-password'

      eventHandler.listen = async (type: StoreEventType, key: string, callback: Function) => {
        if (type == 'extract_key-approval') {
          callback({ identifier: eventHandler.identifier, password: extractPassword })
          return
        }
        if (type == 'generate_key-approval') {
          callback({ password: 'generate-password' })
          return
        }

        callback(key)
      }

      await keyStore.extractKey('credential')
      extractPassword = 'extract-password'

      await expect(keyStore.extractKey('credential')).to.be.rejected

      extractPassword = 'generate-password'
      const extractedKeyPair = await keyStore.extractKey('credential')

      expect(extractedKeyPair.identifier).to.eq('test-key')
    })

    it('retrieves key pairs through the extract key approval password', async () => {
      const storage = new MemoryStorage()
      const eventHandler = new KeyEventHandler('test-key', 'password')
      const keyStore = new KeyStore(eventHandler, storage)

      const generatedKeyPair = await keyStore.extractKey('credential')
      const extractedKeyPair = await keyStore.extractKey('credential')

      expect(extractedKeyPair.identifier).to.eq('test-key')
      expect(extractedKeyPair.did).to.eq(generatedKeyPair.did)
    })

    it('rejects when an encrypted key pair is retrieved with the wrong password', async () => {
      const storage = new MemoryStorage()
      const eventHandler = new KeyEventHandler('test-key', 'password')
      const keyStore = new KeyStore(eventHandler, storage)

      await keyStore.extractKey('credential')
      eventHandler.password = 'wrong-password'

      await expect(keyStore.extractKey('credential')).to.be.rejected
    })
  })
})
