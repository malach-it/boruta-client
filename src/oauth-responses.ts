type OauthErrorParams = {
  error: string
  error_description: string
  status: number
}
export class OauthError extends Error {
  error: string
  error_description: string
  status: number

  constructor({ status, error, error_description }: OauthErrorParams) {
    super()

    this.status = status
    this.error = error
    this.error_description = error_description
  }

  get message() {
    return this.error_description || 'An unknown error occured.'
  }
}

export interface ImplicitSuccess {
  access_token: string
  id_token?: string
  expires_in: number
  state?: string
}

export interface ClientCredentialsSuccess {
  token_type: string
  access_token: string
  expires_in: number
  refresh_token?: string
  state?: string
}

