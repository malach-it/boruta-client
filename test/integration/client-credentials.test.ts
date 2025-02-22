import "mocha"
import chai  from 'chai'
const { expect } = chai
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
      const message = 'request could not be processed'
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
          .post(oauth.tokenPath || '')
          .reply(200, tokenSuccess)
      })

      it('should resolve an oauth response', async () => {
        return expect(client.getToken()).to.eventually.deep.eq(tokenSuccess)
      })
    })
  })
})
