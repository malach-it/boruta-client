import axios from 'axios'
import { OauthError, TokenSuccess } from './oauth-responses'

export type BorutaOauthParams = {
  host: string
  tokenPath: string
}

export type ClientCredentialsParams = {
  clientId: string
  clientSecret: string
}

type createClientCredentialsParams =  {
  oauth: BorutaOauth
}
function createClientCredentialsClient({ oauth }: createClientCredentialsParams) {
  return class ClientCredentials {
    oauth: BorutaOauth
    clientId: string
    clientSecret: string

    constructor({ clientId, clientSecret }: ClientCredentialsParams) {
      this.oauth = oauth
      this.clientId = clientId
      this.clientSecret = clientSecret
    }

    getToken(): Promise<TokenSuccess> {
      const { oauth: { api, tokenPath } } = this
      return api.post<TokenSuccess>(tokenPath, {}).then((response) => {
        return response.data
      }).catch(({ status, response }) => {
        throw new OauthError({ status, ...response.data })
      })
    }
  }
}


export class BorutaOauth {
  host: string
  tokenPath: string

  constructor ({ host, tokenPath }: BorutaOauthParams) {
    this.host = host
    this.tokenPath = tokenPath
  }

  get api() {
    return axios.create({
      baseURL: this.host,
      timeout: 1000
    })
  }

  get ClientCredentials() {
    return createClientCredentialsClient({ oauth: this })
  }
}
