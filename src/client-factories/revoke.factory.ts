import axios from 'axios'
import { BorutaOauth } from "../boruta-oauth"
import { OauthError } from "../oauth-responses"

export type RevokeFactoryParams =  {
  oauth: BorutaOauth
  window: Window
}

export type RevokeParams = {
  clientId: string
  clientSecret?: string
}

export type RevokePostData = {
  client_id: string
  token: string
  client_secret?: string
}

export function createRevokeClient({ oauth, window }: RevokeFactoryParams) {
  return class Revoke {
    oauth: BorutaOauth
    clientId: string
    clientSecret?: string

    constructor({ clientId, clientSecret }: RevokeParams) {
      this.oauth = oauth
      this.clientId = clientId
      this.clientSecret = clientSecret
    }

    revoke(token: string): Promise<void> {
      const { revokePath } = oauth
      if (!revokePath) return Promise.reject()

      const { clientId, clientSecret } = this
      const data: RevokePostData = {
        client_id: this.clientId,
        token: token
      }
      if (clientSecret) data['client_secret'] = clientSecret

      return oauth.api.post(revokePath, data)
        .then(() => {})
        .catch(({ status, response }) => {
          throw new OauthError({ status, ...response.data })
        })
    }
  }
}
