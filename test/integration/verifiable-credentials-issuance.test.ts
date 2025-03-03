import "mocha"
import chai  from 'chai'
const { assert, expect } = chai
import chaiAsPromised from 'chai-as-promised'
import nock from 'nock'
import { stubInterface } from 'ts-sinon'
import { BorutaOauth } from '../../src/boruta-oauth'
import { BrowserStorage } from '../../src/storage'
import { EventHandler, StoreEventType } from '../../src/event-handler'
import { OauthError, TokenSuccess } from "../../src/oauth-responses"
import { PRIVATE_KEY_STORAGE_KEY, PUBLIC_KEY_STORAGE_KEY } from '../../src/constants'
chai.use(chaiAsPromised)

class EventHandlerMock implements EventHandler {
  async dispatch(type: StoreEventType, key: string) {}
  async listen(type: StoreEventType, key: string, callback: () => void) {
    return callback()
  }
}

describe('BorutaOauth', () => {
  const window = stubInterface<Window>()
  Object.defineProperty(window, 'localStorage', {
    value: stubInterface<Storage>(),
    writable: true
  })
  const host = 'http://test.host'
  const tokenPath = '/token'
  const credentialPath = '/credential'
  const storage = new BrowserStorage(window)
  const eventHandler = new EventHandlerMock()
  const oauth = new BorutaOauth({ host, tokenPath, credentialPath, window, storage, eventHandler })
  beforeEach(() => {
    // @ts-ignore
    window.localStorage.getItem.withArgs(PRIVATE_KEY_STORAGE_KEY).returns(undefined)
    // @ts-ignore
    window.localStorage.getItem.withArgs(PUBLIC_KEY_STORAGE_KEY).returns(undefined)
  })
  afterEach(() => {
    nock.cleanAll()
  })

  describe('VerifiableCredentialsIssuance client is setup', () => {
    const clientId = 'clientId'
    const clientSecret = 'clientSecret'
    const redirectUri = 'http://redirect.uri'
    const client = new oauth.VerifiableCredentialsIssuance({ clientId, clientSecret, redirectUri })

    describe('#parsePreauthorizedCodeResponse', () => {
      describe('location with no query', () => {
        beforeEach(() => {
          Object.defineProperty(window.location, 'search', {
            writable: true,
            value: ''
          })
        })

        it('returns an error', async () => {
          client.parsePreauthorizedCodeResponse(window.location)
            .then(() => {
              assert(false)
            }).catch(error => {
              expect(error.message).to.eq('Could not parse location.')
            })
        })
      })

      describe('location with oauth error response', () => {
        const error = 'bad_request'
        const error_description = 'Error description'
        beforeEach(() => {
          Object.defineProperty(window.location, 'search', {
            writable: true,
            value: `#error=${error}&error_description=${error_description}`
          })
        })

        it('returns an error', async () => {
          client.parsePreauthorizedCodeResponse(window.location)
            .then(() => {
              assert(false)
            }).catch(error => {
              expect(error.message).to.eq(error_description)
            })
        })
      })

      describe('location with preauthorized code successful response', () => {
        const preauthorizedCode = 'preauthorized_code'
        const credential_issuer = 'issuer'
        beforeEach(() => {
          Object.defineProperty(window.location, 'search', {
            writable: true,
            value: `?credential_offer=${encodeURI(JSON.stringify({
              credential_issuer,
              grants: {
                'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                  'pre-authorized_code': preauthorizedCode
                }
              }
            }))}`
          })
        })

        it('returns a credential offer response', async () => {
          const response = await client.parsePreauthorizedCodeResponse(window.location)

          expect(response).to.deep.eq({
            credential_issuer,
            preauthorized_code: preauthorizedCode
          })
        })
      })
    })

    describe('#getToken', () => {
      const preauthorizedCode = 'preauthorized_code'

      describe('OAuth request is a failure', () => {
        beforeEach(() => {
          nock(host)
            .post(tokenPath)
            .reply(500, {})
        })

        it('should reject with an error', async () => {
          const message = 'An unknown error occured.'

          return expect(client.getToken(preauthorizedCode)).to.be.rejectedWith(OauthError, message)
        })
      })

      describe('OAuth request returns an error', () => {
        const message = 'request couls not be processed'
        beforeEach(() => {
          nock(host)
            .post(tokenPath)
            .reply(400, {error: 'bad_request', error_description: message})
        })

        it('should reject with an error', async () => {
          return expect(client.getToken(preauthorizedCode)).to.be.rejectedWith(OauthError, message)
        })
      })

      describe('OAuth request is a success', () => {
        const tokenSuccess: TokenSuccess = {
          token_type: 'bearer',
          access_token: 'access_token',
          expires_in: 3600,
          authorization_details: []
        }
        beforeEach(() => {
          nock(oauth.host)
            .post(oauth.tokenPath || '')
            .reply(200, tokenSuccess)
        })

        it('should resolve an oauth response', async () => {
          return expect(client.getToken(preauthorizedCode)).to.eventually.deep.eq(tokenSuccess)
        })
      })
    })

    describe('#getCredential', () => {
      const tokenSuccess = {
        token_type: 'bearer',
        access_token: 'access_token',
        expires_in: 3600,
        authorization_details: []
      }
      const credentialIdentifier = 'credential_identifier'
      const format = 'format'

      describe('OAuth request is a failure', () => {
        beforeEach(() => {
          nock(host)
            .post(credentialPath)
            .reply(500, {})
        })

        it('should reject with an error', async () => {
          const message = 'An unknown error occured.'

          return expect(
            client.getCredential(tokenSuccess, credentialIdentifier, format)
          ).to.be.rejectedWith(OauthError, message)
        })
      })

      describe('OAuth request returns an error', () => {
        const message = 'request couls not be processed'
        beforeEach(() => {
          nock(host)
            .post(credentialPath)
            .reply(400, {error: 'bad_request', error_description: message})
        })

        it('should reject with an error', async () => {
          return expect(
            client.getCredential(tokenSuccess, credentialIdentifier, format)
          ).to.be.rejectedWith(OauthError, message)
        })
      })

      describe('OAuth request is a success', () => {
        const credentialSuccess = {
          format: 'format',
          credential: 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHhoSnFlQUhROVBoaldBUVlnZlNyZlg5SEpaRTQxd0M3c2NUaHlGcmo5dllWOE5pMkx0V29EMkNhQnR3ZkNycEJ6MThiSHZoTkhndmhVeEhidHFocVRRcWFGcXVwMkdQcGZkMXNEazc5QWJiYXphYjNvb2ZWZFZZY2pBbW1kWTNtZSN6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JweGhKcWVBSFE5UGhqV0FRWWdmU3JmWDlISlpFNDF3QzdzY1RoeUZyajl2WVY4TmkyTHRXb0QyQ2FCdHdmQ3JwQnoxOGJIdmhOSGd2aFV4SGJ0cWhxVFFxYUZxdXAyR1BwZmQxc0RrNzlBYmJhemFiM29vZlZkVlljakFtbWRZM21lIiwidHlwIjoiZGMrc2Qtand0In0.eyJfc2QiOlsiTVBaMFlGQlp4eGNFR1lzcFpqY2hKaktvWEVxOVlqem5tSFFNYmEzRlpNSSJdLCJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiUFl3bkJVa0lOcWFQSmJmb2daRi1LeHhLLXJ0dExEMFdid1VuV1BvY3JWYyIsInkiOiJqajZMVmNNNGw2ZmM5bi1JVllWeVo2UklSU21MaGZMSnNGaGRSTThVZ0FRIn19LCJleHAiOjE3NzI1NDk5ODQsImlhdCI6MTc0MTAxMzk4NCwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JweGhKcWVBSFE5UGhqV0FRWWdmU3JmWDlISlpFNDF3QzdzY1RoeUZyajl2WVY4TmkyTHRXb0QyQ2FCdHdmQ3JwQnoxOGJIdmhOSGd2aFV4SGJ0cWhxVFFxYUZxdXAyR1BwZmQxc0RrNzlBYmJhemFiM29vZlZkVlljakFtbWRZM21lIiwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwdFdGVWVVSkhodjJEaDd6RVFDUU1wNFpDTFhDWTVFdFpxQlREQ2Z2eFJNVFRkNDc2NlozdDRCd0ZGQzlCb1k0ZmdqTEh0N2VhRzlIeFZqRzVFU1E0bzVQSzdoRkR6aFR2V1NlUlM0dTVOejl6V2VRRk1VaVQ0Z3h4ZmR2ZVpuNjJnIiwidmN0IjpudWxsfQ.MUhJoMN8yR_pM6z4eFj-AQvWriptJtftrwh9QrkhVFajDfN7BU2niXNlDnSKE5pc6xEOe4KPkhfht_KwkwcsmA~WyJCaTl4YUJ2Q2hzS293NkhDa0NRQX43MWUzY2ZmMyIsInRlc3QiLCJhZG1pbkB0ZXN0LnRlc3QiXQ~'
        }
        beforeEach(() => {
          nock(oauth.host)
            .post(credentialPath)
            .reply(200, credentialSuccess)
        })

        it('should resolve an oauth response', async () => {
          return expect(
            client.getCredential(tokenSuccess, credentialIdentifier, format)
          ).to.eventually.deep.eq(credentialSuccess)
        })
      })
    })
  })
})
