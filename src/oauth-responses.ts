type OauthErrorParams = {
  error: string
  error_description: string
}
export class OauthError extends Error {
  error: string
  error_description: string

  constructor({ error, error_description }: OauthErrorParams) {
    super()

    this.error = error
    this.error_description = error_description
  }

  get message() {
    return this.error_description || 'An unknown error occured.'
  }
}

export interface TokenSuccess {
  token_type: string
  access_token: string
  expires_in: number
  refresh_token?: string
  state?: string
}