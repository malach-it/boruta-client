import "mocha"
import chai from 'chai'
const { assert, expect } = chai
import chaiAsPromised from 'chai-as-promised'
import nock from 'nock'
import { stubInterface } from 'ts-sinon'
import { stub } from 'sinon'
import { BorutaOauth } from '../../src/boruta-oauth'
import { OauthError, ImplicitSuccess } from "../../src/oauth-responses"
import { NONCE_KEY, STATE_KEY } from '../../src/client-factories/implicit.factory'
chai.use(chaiAsPromised)

const window = stubInterface<Window>()
Object.defineProperty(window, 'localStorage', {
  value: stubInterface<Storage>(),
  writable: true
})

const siopv2QueryParams = [
  'client_id',
  'redirect_uri',
  'request',
  'response_mode',
  'response_type'
]
type siopv2ParamKey = 'client_id' | 'redirect_uri' | 'request' | 'response_mode' | 'response_type' | 'scope'

describe('BorutaOauth', () => {
  const host = 'http://oauth.boruta.patatoid.fr'
  const jwksPath = '/openid/jwks'
  const oauth = new BorutaOauth({ host, jwksPath, window })
  let siopV2SuccessParams: {
    client_id: string
    redirect_uri: string
    request: string
    response_mode: string
    response_type: string
    scope: string
  }

  beforeEach(() => {
    siopV2SuccessParams = {
      client_id: "00000000-0000-0000-0000-000000000001",
      redirect_uri: "https://oauth.boruta.patatoid.fr/openid/direct_post/6430c043-b3cb-4385-a44b-378947576201",
      request: "eyJhbGciOiJSUzUxMiIsImtpZCI6Im5PSElRM0tNNENIdVZTM1dsIiwidHlwIjoiSldUIn0.eyJhdWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJjbGllbnRfaWQiOiJodHRwczovL29hdXRoLmJvcnV0YS5wYXRhdG9pZC5mciIsImV4cCI6MTcyODc0NzUxNiwiaXNzIjoiaHR0cHM6Ly9vYXV0aC5ib3J1dGEucGF0YXRvaWQuZnIiLCJub25jZSI6bnVsbCwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9vYXV0aC5ib3J1dGEucGF0YXRvaWQuZnIvb3BlbmlkL2RpcmVjdF9wb3N0LzY0MzBjMDQzLWIzY2ItNDM4NS1hNDRiLTM3ODk0NzU3NjIwMSIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJpZF90b2tlbiIsInNjb3BlIjoib3BlbmlkIn0.rLZN1L8EcJfx6S5eyLmPNdP1-w5z3KzSEp9HBX33fOEhIIwn57PrNCVCFQmH3kw4FG5owIA92_bwuZ-UpNejWf_6PtE4Nl-kTzgouN441wIjDYMaSFjHNZZX2ZKqhZzpi2WJSFOqszxfXxmlY-omw7PBu3LMb2Wq6CUTerHURQ8",
      response_mode: "direct_post",
      response_type: "id_token",
      scope: "openid"
    }
  })
  afterEach(() => {
    nock.cleanAll()
  })

  describe('SIOPV2', () => {
    describe('#parseLocation', () => {
      const clientId = 'clientId'
      const redirectUri = 'http://front.host/callback'
      const scope = 'scope'
      const client = new oauth.Siopv2()

      describe('location with no query', () => {
        beforeEach(() => {
          Object.defineProperty(window.location, 'search', {
            writable: true,
            value: ''
          })
        })

        it('returns an error', async () => {
          try {
            await client.parseSiopv2Response(window.location)

            assert(false)
          } catch(error) {
            expect(error.message).to.eq('Siopv2 response location must contain query params.')
          }
        })
      })

      siopv2QueryParams.forEach((param) => {
        describe(`location with missing ${param} params in query`, () => {
          beforeEach(() => {
            delete siopV2SuccessParams[<siopv2ParamKey>param]
            Object.defineProperty(window.location, 'search', {
              writable: true,
              value: new URLSearchParams(siopV2SuccessParams).toString()
            })
          })

          it('returns an error', async () => {
            try {
              await client.parseSiopv2Response(window.location)

              assert(false)
            } catch(error) {
              expect(error.message).to.eq(`${param} parameter is missing in Siopv2 response location.`)
            }
          })
        })
      })

      describe('location with successfull siopv2 response', () => {
        beforeEach(() => {
          Object.defineProperty(window.location, 'search', {
            writable: true,
            value: '?client_id=00000000-0000-0000-0000-000000000001&redirect_uri=https%3A%2F%2Foauth.boruta.patatoid.fr%2Fopenid%2Fdirect_post%2F526a2e3d-8b91-4f24-ae52-392f02bb1b6b&request=eyJhbGciOiJSUzUxMiIsImtpZCI6InV3azlUdHlIS0tBLTNpRm1lIiwidHlwIjoiSldUIn0.eyJhdWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJjbGllbnRfaWQiOiJodHRwczovL29hdXRoLmJvcnV0YS5wYXRhdG9pZC5mciIsImV4cCI6MTcyODc1OTMzMSwiaXNzIjoiaHR0cHM6Ly9vYXV0aC5ib3J1dGEucGF0YXRvaWQuZnIiLCJub25jZSI6bnVsbCwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9vYXV0aC5ib3J1dGEucGF0YXRvaWQuZnIvb3BlbmlkL2RpcmVjdF9wb3N0LzUyNmEyZTNkLThiOTEtNGYyNC1hZTUyLTM5MmYwMmJiMWI2YiIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJpZF90b2tlbiIsInNjb3BlIjoib3BlbmlkIn0.De1vkk_kFsr7ng5H9IksWZ2tFUctN1b8RWBuhBpUXok0p9wugv0j7Jp9yD5RktkLQqfGKK9vKPb2xndkbUQdcM92R9dhUIrOMiQyTwpBNi8Ijduun_b_qRPlo7cJ6lKzKGqCCzhh5zRHOFDOjdP1vy8y5QQ_6vcbX01e0WUpcsw&response_mode=direct_post&response_type=id_token&scope=openid'
          })
        })

        it('returns all parameters', async () => {
          const response = await client.parseSiopv2Response(window.location)

          expect(response).to.deep.eq(siopV2SuccessParams)
        })
      })

      // describe('location with openid connect successful response', () => {
      //   const access_token = 'access_token'
      //   const id_token = 'id_token'
      //   const expires_in = 3600
      //   let state = 'state'
      //   beforeEach(() => {
      //     // @ts-ignore
      //     window.localStorage.getItem.withArgs(STATE_KEY).returns(state)
      //     Object.defineProperty(window.location, 'hash', {
      //       writable: true,
      //       value: `#access_token=${access_token}&id_token=${id_token}&expires_in=${expires_in}&state=${state}`
      //     })
      //   })

      //   it('returns an implicit response', async () => {
      //     const response = await client.parseLocation(window.location)

      //     expect(response).to.deep.eq({
      //       access_token,
      //       expires_in,
      //       id_token,
      //       state
      //     })
      //   })
      // })
    })
  })
})
