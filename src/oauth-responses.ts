export interface OauthError {
  error: string
  error_description: string
}

export interface TokenSuccess {
  token_type: string
  access_token: string
  expires_in: string
  refresh_token?: string
  state?: string
}