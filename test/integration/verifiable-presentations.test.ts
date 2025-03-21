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
import { CREDENTIALS_KEY } from '../../src/constants'
chai.use(chaiAsPromised)

const localStorageCredentials = '[{"credentialId":"BorutaTest","format":"vc+sd-jwt","credential":"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHhoSnFlQUhROVBoaldBUVlnZlNyZlg5SEpaRTQxd0M3c2NUaHlGcmo5dllWOE5pMkx0V29EMkNhQnR3ZkNycEJ6MThiSHZoTkhndmhVeEhidHFocVRRcWFGcXVwMkdQcGZkMXNEazc5QWJiYXphYjNvb2ZWZFZZY2pBbW1kWTNtZSN6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JweGhKcWVBSFE5UGhqV0FRWWdmU3JmWDlISlpFNDF3QzdzY1RoeUZyajl2WVY4TmkyTHRXb0QyQ2FCdHdmQ3JwQnoxOGJIdmhOSGd2aFV4SGJ0cWhxVFFxYUZxdXAyR1BwZmQxc0RrNzlBYmJhemFiM29vZlZkVlljakFtbWRZM21lIiwidHlwIjoiZGMrc2Qtand0In0.eyJfc2QiOlsiTVBaMFlGQlp4eGNFR1lzcFpqY2hKaktvWEVxOVlqem5tSFFNYmEzRlpNSSJdLCJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiUFl3bkJVa0lOcWFQSmJmb2daRi1LeHhLLXJ0dExEMFdid1VuV1BvY3JWYyIsInkiOiJqajZMVmNNNGw2ZmM5bi1JVllWeVo2UklSU21MaGZMSnNGaGRSTThVZ0FRIn19LCJleHAiOjE3NzI1NDk5ODQsImlhdCI6MTc0MTAxMzk4NCwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JweGhKcWVBSFE5UGhqV0FRWWdmU3JmWDlISlpFNDF3QzdzY1RoeUZyajl2WVY4TmkyTHRXb0QyQ2FCdHdmQ3JwQnoxOGJIdmhOSGd2aFV4SGJ0cWhxVFFxYUZxdXAyR1BwZmQxc0RrNzlBYmJhemFiM29vZlZkVlljakFtbWRZM21lIiwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwdFdGVWVVSkhodjJEaDd6RVFDUU1wNFpDTFhDWTVFdFpxQlREQ2Z2eFJNVFRkNDc2NlozdDRCd0ZGQzlCb1k0ZmdqTEh0N2VhRzlIeFZqRzVFU1E0bzVQSzdoRkR6aFR2V1NlUlM0dTVOejl6V2VRRk1VaVQ0Z3h4ZmR2ZVpuNjJnIiwidmN0IjpudWxsfQ.MUhJoMN8yR_pM6z4eFj-AQvWriptJtftrwh9QrkhVFajDfN7BU2niXNlDnSKE5pc6xEOe4KPkhfht_KwkwcsmA~WyJCaTl4YUJ2Q2hzS293NkhDa0NRQX43MWUzY2ZmMyIsInRlc3QiLCJhZG1pbkB0ZXN0LnRlc3QiXQ~","claims":[{"key":"test","value":"admin@test.test"}],"sub":"did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbptWFUeUJHhv2Dh7zEQCQMp4ZCLXCY5EtZqBTDCfvxRMTTd4766Z3t4BwFFC9BoY4fgjLHt7eaG9HxVjG5ESQ4o5PK7hFDzhTvWSeRS4u5Nz9zWeQFMUiT4gxxfdveZn62g"},{"credentialId":"SecondCredential","format":"vc+sd-jwt","credential":"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHhoSnFlQUhROVBoaldBUVlnZlNyZlg5SEpaRTQxd0M3c2NUaHlGcmo5dllWOE5pMkx0V29EMkNhQnR3ZkNycEJ6MThiSHZoTkhndmhVeEhidHFocVRRcWFGcXVwMkdQcGZkMXNEazc5QWJiYXphYjNvb2ZWZFZZY2pBbW1kWTNtZSN6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JweGhKcWVBSFE5UGhqV0FRWWdmU3JmWDlISlpFNDF3QzdzY1RoeUZyajl2WVY4TmkyTHRXb0QyQ2FCdHdmQ3JwQnoxOGJIdmhOSGd2aFV4SGJ0cWhxVFFxYUZxdXAyR1BwZmQxc0RrNzlBYmJhemFiM29vZlZkVlljakFtbWRZM21lIiwidHlwIjoiZGMrc2Qtand0In0.eyJfc2QiOlsiZnlTSHJ5djNpcDVCc2RubXYxTHRUTUltSjFfU1ltbEhtU0lVNEE4d3RRYyIsIlN2akhJMFRmT0JFQ0Rwb1lnTUNNSEFNNldBeEMxNjRiSVFGVGVxZDNJUDAiXSwiY25mIjp7Imp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IlBZd25CVWtJTnFhUEpiZm9nWkYtS3h4Sy1ydHRMRDBXYndVbldQb2NyVmMiLCJ5Ijoiamo2TFZjTTRsNmZjOW4tSVZZVnlaNlJJUlNtTGhmTEpzRmhkUk04VWdBUSJ9fSwiZXhwIjoxNzcyNTUxMDQzLCJpYXQiOjE3NDEwMTUwNDMsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHhoSnFlQUhROVBoaldBUVlnZlNyZlg5SEpaRTQxd0M3c2NUaHlGcmo5dllWOE5pMkx0V29EMkNhQnR3ZkNycEJ6MThiSHZoTkhndmhVeEhidHFocVRRcWFGcXVwMkdQcGZkMXNEazc5QWJiYXphYjNvb2ZWZFZZY2pBbW1kWTNtZSIsInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHRXRlVlVUpIaHYyRGg3ekVRQ1FNcDRaQ0xYQ1k1RXRacUJURENmdnhSTVRUZDQ3NjZaM3Q0QndGRkM5Qm9ZNGZnakxIdDdlYUc5SHhWakc1RVNRNG81UEs3aEZEemhUdldTZVJTNHU1Tno5eldlUUZNVWlUNGd4eGZkdmVabjYyZyIsInZjdCI6IiJ9.bZS96ltM0EoLWC7RKHAo5ox56Lc09tx9jFwgisY9iKWNgRbFty0OV46MwT-RX0MfcW1Wz11SHUOy3iOprW2Zfg~WyJCaTl4d3FjMlhjT0t3NkhDa0NRQX43MWUzY2ZmMyIsInRlc3QuZW1haWwiLCJhZG1pbkB0ZXN0LnRlc3QiXQ~WyJCaTl4d3FjMlhoSERvY0tRSkFBfjcxZTNjZmYzIiwidGVzdC5mb28iLCJiYXIiXQ~","claims":[{"key":"test.email","value":"admin@test.test"},{"key":"test.foo","value":"bar"}],"sub":"did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbptWFUeUJHhv2Dh7zEQCQMp4ZCLXCY5EtZqBTDCfvxRMTTd4766Z3t4BwFFC9BoY4fgjLHt7eaG9HxVjG5ESQ4o5PK7hFDzhTvWSeRS4u5Nz9zWeQFMUiT4gxxfdveZn62g"},{"credentialId": "BorutaCredentialSdJwt","format": "vc+sd-jwt","credential": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6emhRUlk0QTMyeEhvcDJ3cmNXakRZS3VkVHZKQ0Qzb0tYZ01RcHlTR0E1UXUxamJra0tnanhFWFhtY0Facm9RYUVOMktrUzZlSllVeTFWcDZ2b2dRZjJLNTZ0cUZRZjdtN2E5aVNWU0tzVDZSSDVqN2VjQ3dZN0FYM2VaS21vZHBObzZ6NExjalVOcTJQWkhoVHZhQ3lSTHFCM1lDcWN4OWNqY1BqZXhEdVlZN1NaU3YyaTZveGVKVG5EeXlFaU11SkUyNFJ5OFFvUmhHQmpmdFVZb3Y4ZXVza0xDU3FlaDVZTHF5d2plZXhVOUplY29pMm0xdXFua1RVWWEzbUFRRzZYOThlcDhrZW9SazZVd2o2UkdtdGV5VkUiLCJ0cnVzdF9jaGFpbiI6bnVsbCwidHlwIjoiSldUIn0.eyJfc2QiOlsic1JtSnJPNmRKTWp3eGdGbkt2Z3JqOHlobzlpb1N3Vm90dWlFNGFCRklfSSIsIkx5aHZmNG90U2ZMY2IzRENyY1JZZ2diMk5qRGR2U1F5clZESUpOYmJHRDgiLCJiTGxBQV9KZ2k3cG5oTFMzanVTY3ZWRFZWaEliRkFTQkJOa2V0TlVzbkxJIl0sImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJBT0hWOV9ubTVhZmF2eF9LRWNGaXNGY2tSR1NkUldiLXJjQUhjSGJteTlFIiwieSI6ImdhSDlDYXZQbDFIT0xvRjIyYUxZYllGVlhLbkRaY0x6a1ZrZ1lkNUVHZ1EifX0sImV4cCI6MTc3NDExNTkxMiwiaWF0IjoxNzQyNTc5OTEyLCJpc3MiOiJkaWQ6a2V5OnpoUVJZNEEzMnhIb3Ayd3JjV2pEWUt1ZFR2SkNEM29LWGdNUXB5U0dBNVF1MWpia2tLZ2p4RVhYbWNBWnJvUWFFTjJLa1M2ZUpZVXkxVnA2dm9nUWYySzU2dHFGUWY3bTdhOWlTVlNLc1Q2Ukg1ajdlY0N3WTdBWDNlWkttb2RwTm82ejRMY2pVTnEyUFpIaFR2YUN5UkxxQjNZQ3FjeDljamNQamV4RHVZWTdTWlN2Mmk2b3hlSlRuRHl5RWlNdUpFMjRSeThRb1JoR0JqZnRVWW92OGV1c2tMQ1NxZWg1WUxxeXdqZWV4VTlKZWNvaTJtMXVxbmtUVVlhM21BUUc2WDk4ZXA4a2VvUms2VXdqNlJHbXRleVZFIiwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JvaVJlaU41TEpTMkpnR3U5emo4NEhzRFV2eUZrNGM5VG1aYkdaYzg2RTJIRk5SYktmWmhmSnVzVkhHcDNFV3pKdnd0dWpjV3Y1ZTVTa1Fxeld1UlJGaDQ3VXU2dEJYQzRvMW5DeXl6UEg1anpTcE1lQlhScVVUWkd6MkprNDdkWWNMIiwidmN0IjpudWxsfQ.XCdmTWiNo5WWGr6c5NnLPSkU_TLAkcALEqy6r5mNVUnSbnVfHxq4GY0m3WMeAcm3VjJH9klPNvtU4YmdR_l9gdM3OrfMDWBgdYjrVLTsvGK6tVP645x04nNsgR1MEURRagVYo_k6Au889kRsIccqYbeDm76bXY7i6BAm9pI2pU4~WyJCakREbmdEQ3RNS3hHTU9od3BBa0FBfjM1MTlhZWU5IiwiYm9ydXRhX3VpZCIsImM4OTVlODc3LWY3MTAtNDgwNi04YjIwLWQxNTI5NmZjYjJjOCJd~WyJCakREbmdEQ3RNS3hZY09od3BBa0FBfjM1MTlhZWU5IiwiZW1haWwiLCJhZG1pbkB0ZXN0LnRlc3QiXQ~WyJCakREbmdEQ3RNS3h3b1hEb2NLUUpBQX4zNTE5YWVlOSIsImZvbyIsImFkbWluQHRlc3QudGVzdCJd~"}]'

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
  const storage = new BrowserStorage(window)
  const eventHandler = new EventHandlerMock()
  const oauth = new BorutaOauth({ host, storage, eventHandler })
  beforeEach(() => {
    // @ts-ignore
    window.localStorage.getItem.withArgs(CREDENTIALS_KEY).returns(localStorageCredentials)
  })
  afterEach(() => {
    nock.cleanAll()
  })

  describe('VerifiablePresentation client is setup', () => {
    const clientId = 'clientId'
    const redirectUri = 'http://redirect.uri'
    const client = new oauth.VerifiablePresentations({ clientId, redirectUri })

    describe('#generatePresentation', () => {
      describe('with an invalid presentation authorization', () => {
        const presentationAuthorization = {
          request: "invalid",
          presentation_definition: {
            id: 'test',
            input_descriptors: []
          },
          client_id: "8020f8e5-9d2d-4a15-8eab-aa3fb29330e3",
          redirect_uri: "http://localhost:4000/openid/direct_post/b085124e-e721-482e-ac3e-4271719ec7d5",
          response_mode: "post",
          response_type: "vp_token"
        }

        it('returns an error', async () => {
          return client.generatePresentation(presentationAuthorization)
            .then(() => {
              assert(false)
            }).catch(error => {
              expect(error.message).to.eq('JWTInvalid: Invalid JWT')
            })
        })
      })

      describe('with a valid presentation authorization', () => {
        const presentationAuthorization = {
          request: "eyJhbGciOiJFUzI1NiIsImtpZCI6IjI4UlBXWkZtajdLdW5zdGdnIiwidHlwIjoiSldUIn0.eyJhdWQiOiI4MDIwZjhlNS05ZDJkLTRhMTUtOGVhYi1hYTNmYjI5MzMwZTMiLCJjbGllbnRfaWQiOiJodHRwOi8vbG9jYWxob3N0OjQwMDAiLCJleHAiOjE3NDExMjM4OTQsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMCIsIm5vbmNlIjpudWxsLCJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6ImNyZWRlbnRpYWwiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJmaWx0ZXIiOnsicGF0dGVybiI6ImJhciIsInR5cGUiOiJzdHJpbmcifSwicGF0aCI6WyIkLmZvbyJdfV19LCJmb3JtYXQiOnsidmMrc2Qtand0Ijp7InByb29mX3R5cGUiOlsiand0Il19fSwiaWQiOiJmb28ifV19LCJyZWRpcmVjdF91cmkiOiJodHRwOi8vbG9jYWxob3N0OjQwMDAvb3BlbmlkL2RpcmVjdF9wb3N0L2IwODUxMjRlLWU3MjEtNDgyZS1hYzNlLTQyNzE3MTllYzdkNSIsInJlc3BvbnNlX21vZGUiOiJwb3N0IiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwic2NvcGUiOiJvcGVuaWQifQ.UlQ6GKZpEyW-sD6IV6_1xZSLMShK9VZ5w5ZGjgGTnbCLGz10MM4Bgl-1Yskkbz8TBUXi-ufBYJfx_bFktH-3SA",
          presentation_definition: {
            id: 'test',
            input_descriptors: [{
              "constraints": {
                "fields": [
                  {
                    "filter": {
                      "pattern": "bar",
                      "type": "string"
                    },
                    "path": [
                      "$.foo"
                    ]
                  }
                ]
              },
              "format": {
                "vc+sd-jwt": {
                  "proof_type": [
                    "jwt"
                  ]
                }
              },
              "id": "foo"
            }]
          },
          client_id: "8020f8e5-9d2d-4a15-8eab-aa3fb29330e3",
          redirect_uri: "https://verifier.host/openid/direct_post/b085124e-e721-482e-ac3e-4271719ec7d5",
          response_mode: "post",
          response_type: "vp_token"
        }

        describe('verifier respond with an error', () => {
          const error = 'error'
          const error_description = 'error_description'

          beforeEach(() => {
            nock('https://verifier.host')
            .post('/openid/direct_post/b085124e-e721-482e-ac3e-4271719ec7d5')
            .reply(400, { error, error_description })
          })

          it('returns presentation result', async () => {
            const result = await client.generatePresentation(presentationAuthorization)
            assert(result.vp_token)
            assert(result.presentation_submission)
            expect(result.redirect_uri).to.eq('https://verifier.host/openid/direct_post/b085124e-e721-482e-ac3e-4271719ec7d5')
            expect(result.credentials).to.deep.eq([
              {
                credentialId: 'BorutaCredentialSdJwt',
                format: 'vc+sd-jwt',
                credential: 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6emhRUlk0QTMyeEhvcDJ3cmNXakRZS3VkVHZKQ0Qzb0tYZ01RcHlTR0E1UXUxamJra0tnanhFWFhtY0Facm9RYUVOMktrUzZlSllVeTFWcDZ2b2dRZjJLNTZ0cUZRZjdtN2E5aVNWU0tzVDZSSDVqN2VjQ3dZN0FYM2VaS21vZHBObzZ6NExjalVOcTJQWkhoVHZhQ3lSTHFCM1lDcWN4OWNqY1BqZXhEdVlZN1NaU3YyaTZveGVKVG5EeXlFaU11SkUyNFJ5OFFvUmhHQmpmdFVZb3Y4ZXVza0xDU3FlaDVZTHF5d2plZXhVOUplY29pMm0xdXFua1RVWWEzbUFRRzZYOThlcDhrZW9SazZVd2o2UkdtdGV5VkUiLCJ0cnVzdF9jaGFpbiI6bnVsbCwidHlwIjoiSldUIn0.eyJfc2QiOlsic1JtSnJPNmRKTWp3eGdGbkt2Z3JqOHlobzlpb1N3Vm90dWlFNGFCRklfSSIsIkx5aHZmNG90U2ZMY2IzRENyY1JZZ2diMk5qRGR2U1F5clZESUpOYmJHRDgiLCJiTGxBQV9KZ2k3cG5oTFMzanVTY3ZWRFZWaEliRkFTQkJOa2V0TlVzbkxJIl0sImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJBT0hWOV9ubTVhZmF2eF9LRWNGaXNGY2tSR1NkUldiLXJjQUhjSGJteTlFIiwieSI6ImdhSDlDYXZQbDFIT0xvRjIyYUxZYllGVlhLbkRaY0x6a1ZrZ1lkNUVHZ1EifX0sImV4cCI6MTc3NDExNTkxMiwiaWF0IjoxNzQyNTc5OTEyLCJpc3MiOiJkaWQ6a2V5OnpoUVJZNEEzMnhIb3Ayd3JjV2pEWUt1ZFR2SkNEM29LWGdNUXB5U0dBNVF1MWpia2tLZ2p4RVhYbWNBWnJvUWFFTjJLa1M2ZUpZVXkxVnA2dm9nUWYySzU2dHFGUWY3bTdhOWlTVlNLc1Q2Ukg1ajdlY0N3WTdBWDNlWkttb2RwTm82ejRMY2pVTnEyUFpIaFR2YUN5UkxxQjNZQ3FjeDljamNQamV4RHVZWTdTWlN2Mmk2b3hlSlRuRHl5RWlNdUpFMjRSeThRb1JoR0JqZnRVWW92OGV1c2tMQ1NxZWg1WUxxeXdqZWV4VTlKZWNvaTJtMXVxbmtUVVlhM21BUUc2WDk4ZXA4a2VvUms2VXdqNlJHbXRleVZFIiwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JvaVJlaU41TEpTMkpnR3U5emo4NEhzRFV2eUZrNGM5VG1aYkdaYzg2RTJIRk5SYktmWmhmSnVzVkhHcDNFV3pKdnd0dWpjV3Y1ZTVTa1Fxeld1UlJGaDQ3VXU2dEJYQzRvMW5DeXl6UEg1anpTcE1lQlhScVVUWkd6MkprNDdkWWNMIiwidmN0IjpudWxsfQ.XCdmTWiNo5WWGr6c5NnLPSkU_TLAkcALEqy6r5mNVUnSbnVfHxq4GY0m3WMeAcm3VjJH9klPNvtU4YmdR_l9gdM3OrfMDWBgdYjrVLTsvGK6tVP645x04nNsgR1MEURRagVYo_k6Au889kRsIccqYbeDm76bXY7i6BAm9pI2pU4~WyJCakREbmdEQ3RNS3h3b1hEb2NLUUpBQX4zNTE5YWVlOSIsImZvbyIsImFkbWluQHRlc3QudGVzdCJd~',
                claims: [
                  {
                    "key": "foo",
                    "value": "admin@test.test"
                  }
                ],
                disclosures: [
                  {
                    "encoded": "WyJCakREbmdEQ3RNS3h3b1hEb2NLUUpBQX4zNTE5YWVlOSIsImZvbyIsImFkbWluQHRlc3QudGVzdCJd",
                    "key": "foo",
                    "value": "admin@test.test"
                  }
                ],
                sub: 'did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KboiReiN5LJS2JgGu9zj84HsDUvyFk4c9TmZbGZc86E2HFNRbKfZhfJusVHGp3EWzJvwtujcWv5e5SkQqzWuRRFh47Uu6tBXC4o1nCyyzPH5jzSpMeBXRqUTZGz2Jk47dYcL'
              }

            ])
          })
        })
      })
    })
  })
})
