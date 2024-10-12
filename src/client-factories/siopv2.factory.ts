import { BorutaOauth } from "../boruta-oauth"
import { OauthError, Siopv2Success } from "../oauth-responses"
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { SignJWT, exportJWK, exportPKCS8, importJWK, generateKeyPair } from "jose";

export type Siopv2FactoryParams =  {
  oauth: BorutaOauth
  window: Window
}

export type Siopv2Params =  {
}

const PUBLIC_KEY_STORAGE_KEY = 'wallet_public_key'
const PRIVATE_KEY_STORAGE_KEY = 'wallet_private_key'

export function createSiopv2Client({ oauth, window }: Siopv2FactoryParams) {
  return class Siopv2 {
    oauth: BorutaOauth
    publicKey?: any
    privateKey?: any
    did?: any

    constructor() {
      this.oauth = oauth
    }

    async parseSiopv2Response(location: Location): Promise<Siopv2Success> {
      if (location.search === '') {
        return Promise.reject(new OauthError({
          error: 'unkown_error',
          error_description: 'Siopv2 response location must contain query params.'
        }))
      }

      const params = new URLSearchParams(location.search)
      const {
        client_id,
        redirect_uri,
        request,
        response_mode,
        response_type,
        scope
      } = await parseSiopv2Params(params)

      if (!oauth.jwksPath) {
        return Promise.reject(new OauthError({
          error: 'unkown_error',
          error_description: 'You must provide server jwks path.'
        }))
      }

      // TODO verify request signature
      // await oauth.api.get<jwksResponse>(oauth.jwksPath).then(({ data }) => {
      //   const keys = data.keys
      //   let jwt
      //   while (true) {
      //     const key = keys.pop()
      //     if (!key) {
      //       throw new OauthError({
      //         error: 'unknown_error',
      //         error_description: 'Request signature could not be verified.'
      //       })
      //     }
      //     console.log(request)
      //     console.log(key)
      //     jwt = verify(request, key, (err, decoded) => console.log(decoded))
      //     console.log(jwt)
      //   }
      // })



      const { privateKey, did } = await extractKeys()
      const now = Math.floor((new Date()) as unknown as number / 1000)
      const payload = {
        "iss": did,
        "sub": did,
        "aud": redirect_uri,
        "nonce": "nonce",
        "exp": now + 600,
        "iat": now
      }

      const id_token = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'ES256', kid: did })
        .sign(privateKey)

      return {
        id_token,
        client_id,
        redirect_uri,
        request,
        response_mode,
        response_type,
        scope
      }
    }
  }
}

function parseSiopv2Params(params: URLSearchParams): Promise<Siopv2Success> {
  const client_id = params.get('client_id')
  if (!client_id) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'client_id parameter is missing in Siopv2 response location.'
    }))
  }
  const redirect_uri = params.get('redirect_uri')
  if (!redirect_uri) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'redirect_uri parameter is missing in Siopv2 response location.'
    }))
  }
  const request = params.get('request')
  if (!request) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'request parameter is missing in Siopv2 response location.'
    }))
  }
  const response_mode = params.get('response_mode')
  if (!response_mode) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'response_mode parameter is missing in Siopv2 response location.'
    }))
  }
  const response_type = params.get('response_type')
  if (!response_type) {
    return Promise.reject(new OauthError({
      error: 'unkown_error',
      error_description: 'response_type parameter is missing in Siopv2 response location.'
    }))
  }
  const scope = params.get('scope') || undefined

  return Promise.resolve({
    id_token: '',
    client_id,
    redirect_uri,
    request,
    response_mode,
    response_type,
    scope
  })
}

async function extractKeys() {
  let publicKeyJwk, publicKey, privateKey

  if (window.localStorage.getItem(PUBLIC_KEY_STORAGE_KEY) && window.localStorage.getItem(PRIVATE_KEY_STORAGE_KEY)) {
    publicKeyJwk = JSON.parse(window.localStorage.getItem(PUBLIC_KEY_STORAGE_KEY))
    publicKey = await importJWK(publicKeyJwk, 'ES256')
    privateKey = await importJWK(JSON.parse(window.localStorage.getItem(PRIVATE_KEY_STORAGE_KEY)), 'ES256')
  } else {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true })
    publicKeyJwk = await exportJWK(publicKey)
    window.localStorage.setItem(PUBLIC_KEY_STORAGE_KEY, JSON.stringify(publicKeyJwk))
    window.localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, JSON.stringify(await exportJWK(privateKey)))
  }

  const did = EbsiWallet.createDid("NATURAL_PERSON", publicKeyJwk)
  return { publicKey, privateKey, did }
}
