import "mocha"
import chai  from 'chai'
const { assert, expect } = chai
import chaiAsPromised from 'chai-as-promised'
import nock from 'nock'
import { stubInterface } from 'ts-sinon'
import { BorutaOauth } from '../../src/boruta-oauth'
import { OauthError, TokenSuccess } from "../../src/oauth-responses"
import { PRIVATE_KEY_STORAGE_KEY, PUBLIC_KEY_STORAGE_KEY } from '../../src/constants'
chai.use(chaiAsPromised)

describe('BorutaOauth', () => {
  const window = stubInterface<Window>()
  Object.defineProperty(window, 'localStorage', {
    value: stubInterface<Storage>(),
    writable: true
  })
  const host = 'http://test.host'
  const tokenPath = '/token'
  const credentialPath = '/credential'
  const oauth = new BorutaOauth({ host, tokenPath, credentialPath, window })
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
    const client = new oauth.VerifiableCredentialsIssuance({ clientId, clientSecret })

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
        beforeEach(() => {
          Object.defineProperty(window.location, 'search', {
            writable: true,
            value: `?credential_offer=${encodeURI(JSON.stringify({
              grants: {
                'urn:ietf:params:oauth:grant-type:pre-authorized_code': preauthorizedCode
              }
            }))}`
          })
        })

        it('returns an implicit response', async () => {
          const response = await client.parsePreauthorizedCodeResponse(window.location)

          expect(response).to.deep.eq({
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
          credential: 'credential'
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
