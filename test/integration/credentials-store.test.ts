import "mocha"
import chai from 'chai'
const { expect } = chai
import chaiAsPromised from 'chai-as-promised'
import { CredentialsStore } from '../../src/credentials-store'
import { EventHandler, StoreEventType } from '../../src/event-handler'
import { Storage } from '../../src/storage'
import { CREDENTIALS_KEY } from '../../src/constants'

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

class PasswordEventHandler implements EventHandler {
  password: string
  dispatched: Array<{ type: StoreEventType, key: string | undefined }> = []

  constructor (password: string) {
    this.password = password
  }

  async dispatch(type: StoreEventType, key?: string): Promise<void> {
    this.dispatched.push({ type, key })
  }

  async listen(type: StoreEventType, key: string, callback: Function): Promise<void> {
    if (type == 'access_credential-approval') {
      callback(this.password)
      return
    }

    callback(key)
  }

  async remove(type: StoreEventType, key: string, callback: Function): Promise<void> {}
}

const credentialResponse = {
  format: 'jwt_vc',
  credential: [
    'eyJhbGciOiJub25lIn0',
    'eyJjcmVkZW50aWFsU3ViamVjdCI6eyJ0ZXN0X2NyZWRlbnRpYWwiOnsiaWQiOiJkaWQ6ZXhhbXBsZToxMjMiLCJlbWFpbCI6ImFkbWluQHRlc3QudGVzdCJ9fSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpZCI6InRlc3RfY3JlZGVudGlhbCJ9',
    ''
  ].join('.')
}

describe('CredentialsStore', () => {
  describe('#insertCredential', () => {
    it('stores credentials as password-protected JWE entries', async () => {
      const storage = new MemoryStorage()
      const eventHandler = new PasswordEventHandler('password')
      const store = new CredentialsStore(eventHandler, storage)

      await store.insertCredential('test_credential', credentialResponse)

      const storedCredentials = await storage.get<Array<{ jwe: string }>>(CREDENTIALS_KEY)

      expect(eventHandler.dispatched.map(({ type }) => type)).to.include.members([
        'insert_credential-request',
        'access_credential-request'
      ])
      expect(storedCredentials).to.have.length(1)
      expect(storedCredentials?.[0].jwe).to.be.a('string')
      expect(storedCredentials?.[0]).not.to.have.property('credential')
    })
  })

  describe('#credentials', () => {
    it('retrieves credentials through the password approval event', async () => {
      const storage = new MemoryStorage()
      const eventHandler = new PasswordEventHandler('password')
      const store = new CredentialsStore(eventHandler, storage)

      await store.insertCredential('test_credential', credentialResponse)

      const credentials = await store.credentials()

      expect(eventHandler.dispatched.map(({ type }) => type)).to.include('access_credential-request')
      expect(credentials[0].credentialId).to.eq('test_credential')
      expect(credentials[0].credential).to.eq(credentialResponse.credential)
    })

    it('rejects when credentials are retrieved with the wrong password', async () => {
      const storage = new MemoryStorage()
      const eventHandler = new PasswordEventHandler('password')
      const store = new CredentialsStore(eventHandler, storage)

      await store.insertCredential('test_credential', credentialResponse)
      eventHandler.password = 'wrong-password'

      await expect(store.credentials()).to.be.rejected
    })
  })
})
