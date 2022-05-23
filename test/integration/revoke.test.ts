import "mocha"
import chai, { expect }  from 'chai'
import chaiAsPromised from 'chai-as-promised'
import nock from 'nock'
import { stubInterface } from 'ts-sinon'
import { BorutaOauth } from '../../src/boruta-oauth'
import { OauthError } from "../../src/oauth-responses"
chai.use(chaiAsPromised)

describe('BorutaOauth', () => {
  const host = 'http://test.host'
  const revokePath = '/revoke'
  const token = 'token'
  const window = stubInterface<Window>()
  const oauth = new BorutaOauth({ host, revokePath, window })
  afterEach(() => {
    nock.cleanAll()
  })

  describe('Revoke client is setup', () => {
    const clientId = 'clientId'
    const clientSecret = 'clientSecret'
    const client = new oauth.Revoke({ clientId, clientSecret })

    describe('OAuth request is a failure', () => {
      beforeEach(() => {
        nock(host)
          .post(revokePath)
          .reply(500, {})
      })

      it('should reject with an error', async () => {
        const message = 'An unknown error occured.'

        return expect(client.revoke(token)).to.be.rejectedWith(OauthError, message)
      })
    })

    describe('OAuth request returns an error', () => {
      const message = 'request couls not be processed'
      beforeEach(() => {
        nock(host)
          .post(revokePath)
          .reply(400, {error: 'bad_request', error_description: message})
      })

      it('should reject with an error', async () => {
        return expect(client.revoke(token)).to.be.rejectedWith(OauthError, message)
      })
    })

    describe('OAuth request is a success', () => {
      beforeEach(() => {
        nock(oauth.host)
          .post(oauth.revokePath || '')
          .reply(200, '')
      })

      it('should resolve an oauth response', async () => {
        return expect(client.revoke(token)).to.be.fulfilled
      })
    })
  })
})
