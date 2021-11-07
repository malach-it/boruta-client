import "mocha"
import chai, { assert, expect }  from 'chai'
import chaiAsPromised from 'chai-as-promised'
import nock from 'nock'
import { stubInterface, stubObject } from 'ts-sinon'
import { stub } from 'sinon'
import { BorutaOauth } from '../../src/boruta-oauth'
import { OauthError, ImplicitSuccess } from "../../src/oauth-responses"
chai.use(chaiAsPromised)

describe('BorutaOauth', () => {
  const host = 'http://test.host'
  const tokenPath = '/token'
  const authorizePath = '/authorize'
  const window = stubInterface<Window>()
  const oauth = new BorutaOauth({ host, authorizePath, tokenPath, window })
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
          try {
            const response = await client.parseLocation(window.location)

            assert(false)
          } catch(error) {
            expect(error.message).to.eq('Could not be able to parse location.')
          }
        })
      })

      describe('location with oauth error response', () => {
        const error = 'bad_request'
        const error_description = 'Error description'
        const state = 'state'
        beforeEach(() => {
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: `#error=${error}&error_description=${error_description}&state=${state}`
          })
        })

        it('returns an error', async () => {
          try {
            const response = await client.parseLocation(window.location)
          } catch (error) {
            expect(error.message).to.eq(error_description)
          }
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
        const state = 'state'
        beforeEach(() => {
          Object.defineProperty(window.location, 'hash', {
            writable: true,
            value: `#access_token=${access_token}&id_token=${id_token}&expires_in=${expires_in}&state=${state}`
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

    describe('loginUrl', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const scope = 'scope'
      const client = new oauth.Implicit({ clientId, redirectUri, scope })

      it('returns login URL', () => {
        expect(client.loginUrl).to.eq(
          'http://test.host/authorize?client_id=clientId&redirect_uri=http%3A%2F%2Ffront.host%2Fcallback&scope=scope&response_type=token'
        )
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
        expect(iframe.src).to.eq(
          'http://test.host/authorize?client_id=clientId&redirect_uri=http%3A%2F%2Ffront.host%2Fcallback&scope=scope&response_type=token&prompt=none'
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
          Object.defineProperty(window.parent, 'postMessage', {
            writable: true,
            value: postMessage
          })

          try {
            await client.callback()

            assert(false)
          } catch(error) {
            expect(error).to.deep.eq(response)
            expect(postMessage.lastCall.args).to.deep.eq([JSON.stringify({
              type: 'boruta_error',
              error: response
            }), '*'])
          }
        })

        it('sends response to parent', async () => {
          const postMessage = stub()
          Object.defineProperty(window.parent, 'postMessage', {
            writable: true,
            value: postMessage
          })
          const response = stubInterface<ImplicitSuccess>()
          client.parseLocation = stub().returns(Promise.resolve(response))

          await client.callback()

          expect(postMessage.lastCall.args).to.deep.eq([JSON.stringify({
            type: 'boruta_response',
            response
          }), '*'])
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
          try {
            client.handleSilentRefresh(message)

            assert(false)
          } catch(error) {
            expect(error.message).to.eq('Message is not a valid Boruta OAuth response.')
          }
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
          try {
            client.handleSilentRefresh(message)

            assert(false)
          } catch(error) {
            expect(error.message).to.eq('Message is not a valid Boruta OAuth response.')
          }
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
