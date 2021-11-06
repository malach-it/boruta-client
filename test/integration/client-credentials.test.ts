import "mocha"
import chai, { expect }  from 'chai'
import chaiAsPromised from 'chai-as-promised'
import nock from 'nock'
import { stubInterface } from 'ts-sinon'
import { BorutaOauth } from '../../src/boruta-oauth'
import { OauthError, ClientCredentialsSuccess } from "../../src/oauth-responses"
chai.use(chaiAsPromised)

describe('BorutaOauth', () => {
  const host = 'http://test.host'
  const tokenPath = '/token'
  const window = stubInterface<Window>()
  const oauth = new BorutaOauth({ host, tokenPath, window })
  afterEach(() => {
    nock.cleanAll()
  })

  describe('ClientCredentials client is setup', () => {
    const clientId = 'clientId'
    const clientSecret = 'clientSecret'
    const client = new oauth.ClientCredentials({ clientId, clientSecret })

    describe('OAuth request is a failure', () => {
      beforeEach(() => {
        nock(host)
          .post(tokenPath)
          .reply(500, {})
      })

      it('should reject with an error', async () => {
        const message = 'An unknown error occured.'

        return expect(client.getToken()).to.be.rejectedWith(OauthError, message)
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
        return expect(client.getToken()).to.be.rejectedWith(OauthError, message)
      })
    })

    describe('OAuth request is a success', () => {
      const tokenSuccess: ClientCredentialsSuccess = {
        token_type: 'bearer',
        access_token: 'access_token',
        expires_in: 3600
      }
      beforeEach(() => {
        nock(oauth.host)
          .post(oauth.tokenPath)
          .reply(200, tokenSuccess)
      })

      it('should resolve an oauth response', async () => {
        return expect(client.getToken()).to.eventually.deep.eq(tokenSuccess)
      })
    })
  })

  describe('Implicit grant', () => {
    const clientId = 'clientId'
    const redirectUri = 'http://front.host/callback'
    const client = new oauth.Implicit({ clientId, redirectUri })

    describe('#parseLocation', () => {
      describe('location with no hash', () => {
        beforeEach(() => {
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: ''
          })
        })

        it('returns a null object', () => {
          expect(client.parseLocation(window.location)).to.deep.eq({
            access_token: '',
            expires_in: 0
          })
        })
      })

      describe('location with oauth successful response', () => {
        const access_token = 'access_token'
        const expires_in = 3600
        const state = 'state'
        beforeEach(() => {
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: `#access_token=${access_token}&expires_in=${expires_in}&state=${state}`
          })
        })

        it('returns an implicit response', () => {
          expect(client.parseLocation(window.location)).to.deep.eq({
            access_token,
            expires_in,
            state
          })
        })
      })

      describe('location with openid connect successful response', () => {
        const access_token = 'access_token'
        const id_token = 'id_token'
        const expires_in = 3600
        const state = 'state'
        beforeEach(() => {
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: `#access_token=${access_token}&id_token=${id_token}&expires_in=${expires_in}&state=${state}`
          })
        })

        it('returns an implicit response', () => {
          expect(client.parseLocation(window.location)).to.deep.eq({
            access_token,
            expires_in,
            id_token,
            state
          })
        })
      })
    })
  })
})
