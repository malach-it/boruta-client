import "mocha"
import nock from 'nock'
import { stubInterface } from 'ts-sinon'
import { BorutaClient } from '../../src/boruta-client'
import { OauthError, TokenSuccess } from "../../src/oauth-responses"

describe('client_credentials', () => {
  describe('BorutaClient is setup', () => {
    const client = stubInterface<BorutaClient>()
    
    describe('OAuth request is a failure', () => {
      beforeEach(() => {
        nock(client.host)
          .get(client.tokenPath)
          .reply(500)
      })

      it.skip('should reject with an error')
    })

    describe('OAuth request returns an error', () => {
      beforeEach(() => {
        nock(client.host)
          .get(client.tokenPath)
          .reply(400, stubInterface<OauthError>())
      })

      it.skip('should reject with an error')
    })

    describe('OAuth request is a success', () => {
      beforeEach(() => {
        nock(client.host)
          .get(client.tokenPath)
          .reply(200, stubInterface<TokenSuccess>())
      })

      it.skip('should resolve an oauth response')
    })
  })
})
