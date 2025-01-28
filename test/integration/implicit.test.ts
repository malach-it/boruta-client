import "mocha"
import chai  from 'chai'
const { assert, expect } = chai
import chaiAsPromised from 'chai-as-promised'
import nock from 'nock'
import { stubInterface } from 'ts-sinon'
import sinon from 'sinon'
const { stub } = sinon
import { BorutaOauth } from '../../src/boruta-oauth'
import { OauthError, ImplicitSuccess } from "../../src/oauth-responses"
import { NONCE_KEY, STATE_KEY } from '../../src/constants'
chai.use(chaiAsPromised)

const window = stubInterface<Window>()
Object.defineProperty(window, 'localStorage', {
  value: stubInterface<Storage>(),
  writable: true
})

describe('BorutaOauth', () => {
  const host = 'http://test.host'
  const tokenPath = '/token'
  const authorizePath = '/authorize'
  const oauth = new BorutaOauth({ host, authorizePath, tokenPath, window })
  beforeEach(() => {
  })
  afterEach(() => {
    nock.cleanAll()
  })

  describe('Implicit grant', () => {
    describe('#parseLocation', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const scope = 'scope'
      const client = new oauth.Implicit({ clientId, redirectUri, scope })

      describe('location with no hash', () => {
        beforeEach(() => {
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: ''
          })
        })

        it('returns an error', async () => {
          client.parseLocation(window.location)
            .then(() => {
              assert(false)
            }).catch(error => {
              expect(error.message).to.eq('Could not be able to parse location.')
            })
        })
      })

      describe('location with oauth error response', () => {
        const error = 'bad_request'
        const error_description = 'Error description'
        const state = client.state
        beforeEach(() => {
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: `#error=${error}&error_description=${error_description}&state=${state}`
          })
        })

        it('returns an error', async () => {
          // @ts-ignore
          window.localStorage.getItem.withArgs(STATE_KEY).returns('state')
          client.parseLocation(window.location)
            .then(() => {
              assert(false)
            }).catch(error => {
              expect(error.message).to.eq(error_description)
            })
        })
      })

      describe('location with invalid state', () => {
        const access_token = 'access_token'
        const expires_in = 3600
        const state = client.state
        beforeEach(() => {
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: `#access_token=${access_token}&expires_in=${expires_in}&state=${state}`
          })
        })

        it('returns an error', async () => {
          client.parseLocation(window.location)
            .then(() => {
              assert(false)
            }).catch(error => {
              expect(error.message).to.eq(
                'State does not match with the original given in request.'
              )
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

        it('returns an implicit response', async () => {
          const response = await client.parseLocation(window.location)

          expect(response).to.deep.eq({
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
        let state = 'state'
        beforeEach(() => {
          // @ts-ignore
          window.localStorage.getItem.withArgs(STATE_KEY).returns(state)
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: `#access_token=${access_token}&id_token=${id_token}&state=${state}&expires_in=${expires_in}`
          })
        })

        it('returns an implicit response', async () => {
          const response = await client.parseLocation(window.location)

          expect(response).to.deep.eq({
            access_token,
            expires_in,
            id_token,
            state
          })
        })
      })
    })

    describe('.nonce', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const client = new oauth.Implicit({ clientId, redirectUri })

      it('returns string from localStorage', () => {
        // @ts-ignore
        window.localStorage.getItem.withArgs(NONCE_KEY).returns('nonce')

        expect(client.nonce).to.eq('nonce')
      })

      it('returns random string', () => {
        // @ts-ignore
        window.localStorage.getItem.withArgs(NONCE_KEY).returns('')

        assert(client.nonce.length)
      })
    })

    describe('.state', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const client = new oauth.Implicit({ clientId, redirectUri })

      it('returns string from localStorage', () => {
        // @ts-ignore
        window.localStorage.getItem.withArgs(STATE_KEY).returns('state')

        expect(client.state).to.eq('state')
      })

      it('returns random string', () => {
        // @ts-ignore
        window.localStorage.getItem.withArgs(STATE_KEY).returns('')

        assert(client.state.length)
      })
    })

    describe('.loginUrl', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const scope = 'scope'
      const client = new oauth.Implicit({ clientId, redirectUri, scope })

      it('returns login URL', () => {
        expect(client.loginUrl).to.match(
          /http:\/\/test\.host\/authorize\?client_id=clientId&redirect_uri=http%3A%2F%2Ffront.host%2Fcallback&scope=scope&response_type=token/
        )
      })

      describe("with 'id_token token' response type", () => {
        const responseType = 'id_token token'
        const openidScope = 'openid'
        const responseTypeClient = new oauth.Implicit({ clientId, redirectUri, scope: openidScope, responseType })

        it('returns login URL', () => {
          expect(responseTypeClient.loginUrl).to.match(
          /http:\/\/test\.host\/authorize\?client_id=clientId&redirect_uri=http%3A%2F%2Ffront.host%2Fcallback&scope=openid&response_type=id_token\+token&state=(\w+)&nonce=(\w+)/
          )
        })
      })
    })

    describe('#silentRefresh', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const scope = 'scope'
      const client = new oauth.Implicit({ clientId, redirectUri, scope, silentRefresh: true })

      it.skip('triggered at client instanciation')

      it('creates an iframe', () => {
        const iframe = stubInterface<HTMLIFrameElement>()
        const createElement = stub().returns(iframe)
        const appendChild = stub()
        Object.defineProperty(window.document, 'createElement', {
          writable: true,
          value: createElement
        })
        Object.defineProperty(window.document, 'body', {
          writable: true,
          value: { appendChild }
        })
        client.silentRefresh()

        expect(appendChild.calledOnce).to.eq(true)
        expect(iframe.src).to.match(
          /http:\/\/test.host\/authorize\?client_id=clientId&redirect_uri=http%3A%2F%2Ffront.host%2Fcallback&scope=scope&response_type=token&state=(\w+)&prompt=none/
        )
      })
    })

    describe('#callback', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const scope = 'scope'
      const client = new oauth.Implicit({ clientId, redirectUri, scope })

      describe('when in an iframe', () => {
        beforeEach(() => {
          Object.defineProperty(window, 'frameElement', {
            writable: true,
            value: stubInterface<HTMLIFrameElement>()
          })
        })

        it('returns an error', async () => {
          const response = new OauthError({ error: 'error', error_description: 'Error description.' })
          client.parseLocation = stub().returns(Promise.reject(response))
          const postMessage = stub()
          const host = "test.host"
          Object.defineProperty(window.parent, 'postMessage', {
            writable: true,
            value: postMessage
          })
          Object.defineProperty(window.location, 'origin', {
            writable: true,
            value: host
          })

          try {
            await client.callback()

            assert(false)
          } catch(error) {
            expect(error).to.deep.eq(response)
            expect(postMessage.lastCall.args).to.deep.eq([JSON.stringify({
              type: 'boruta_error',
              error: response
            }), host])
          }
        })

        it('sends response to parent', async () => {
          const postMessage = stub()
          const host = 'test.host'
          Object.defineProperty(window.parent, 'postMessage', {
            writable: true,
            value: postMessage
          })
          Object.defineProperty(window.location, 'origin', {
            writable: true,
            value: host
          })
          const response = stubInterface<ImplicitSuccess>()
          client.parseLocation = stub().returns(Promise.resolve(response))

          await client.callback()

          expect(postMessage.lastCall.args).to.deep.eq([JSON.stringify({
            type: 'boruta_response',
            response
          }), host])
        })
      })

      describe('when not in an iframe', () => {
        beforeEach(() => {
          Object.defineProperty(window, 'frameElement', {
            writable: true,
            value: null
          })
        })

        it('returns an error', async () => {
          const response = stubInterface<OauthError>()
          client.parseLocation = stub().returns(Promise.reject(response))

          try {
            await client.callback()

            assert(false)
          } catch(error) {
            expect(error).to.deep.eq(response)
          }
        })

        it('returns current location parsed', async () => {
          const response = stubInterface<ImplicitSuccess>()
          client.parseLocation = stub().returns(Promise.resolve(response))

          expect(await client.callback()).to.deep.eq(response)
        })
      })
    })

    describe('#handleSilentRefresh', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const scope = 'scope'
      const silentRefreshCallback = stub()
      const client = new oauth.Implicit({ clientId, redirectUri, scope, silentRefreshCallback })
      beforeEach(() => {
        silentRefreshCallback.resetHistory()
      })

      it.skip('is attached to message event on instanciation')

      describe('with an unknow message', () => {
        const message = stubInterface<MessageEvent>()

        it('returns an error', () => {
          expect(client.handleSilentRefresh(message)).to.eq(undefined)
        })
      })

      describe('with an unknow json message', () => {
        const message = stubInterface<MessageEvent>()
        beforeEach(() => {
          Object.defineProperty(message, 'data', {
            writable: true,
            value: JSON.stringify({ unknown: true })
          })
        })

        it('returns an error', () => {
          expect(client.handleSilentRefresh(message)).to.eq(undefined)
        })
      })

      describe('with a boruta_error message', () => {
        const error = new OauthError({
          error: 'error',
          error_description: 'Error description.'
        })
        const message = stubInterface<MessageEvent>()
        beforeEach(() => {
          Object.defineProperty(message, 'data', {
            writable: true,
            value: JSON.stringify({
              type: 'boruta_error',
              error
            })
          })
        })

        it('calls silentRefreshCallback', () => {
          client.handleSilentRefresh(message)

          expect(silentRefreshCallback.callCount).to.eq(1)
          expect(silentRefreshCallback.lastCall.args[0]).to.deep.eq({
            error: 'error',
            error_description: 'Error description.'
          })
        })
      })

      describe('with a boruta_response message', () => {
        const response: ImplicitSuccess = {
          access_token: 'access_token',
          expires_in: 10
        }
        const message = stubInterface<MessageEvent>()
        beforeEach(() => {
          Object.defineProperty(message, 'data', {
            writable: true,
            value: JSON.stringify({
              type: 'boruta_response',
              response
            })
          })
        })

        it('set refresh timer', (done) => {
          const silentRefresh = stub(client, 'silentRefresh')
          client.handleSilentRefresh(message)

          assert(client.refresh)

          setTimeout(() => {
            expect(silentRefresh.callCount).to.eq(1)
            done()
          }, 0)
        })

        it('calls silentRefreshCallback', () => {
          client.handleSilentRefresh(message)

          assert(client.refresh)

          expect(silentRefreshCallback.callCount).to.eq(1)
          expect(silentRefreshCallback.lastCall.args[0]).to.deep.eq(response)
        })
      })
    })
  })
})
