type OauthErrorParams = {
  error: string
  error_description: string
  status?: number
}

export class OauthError extends Error {
  error: string
  error_description: string
  status?: number

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
  // TODO expires_at Date
  expires_in: number
  state?: string
}

export interface PreauthorizedCodeSuccess {
  preauthorized_code: string
  credential_issuer: string
}

export interface ClientCredentialsSuccess {
  token_type: string
  access_token: string
  expires_in: number
  refresh_token?: string
  state?: string
}

export interface TokenSuccess {
  token_type: string
  access_token: string
  expires_in: number
  refresh_token?: string
  state?: string
  authorization_details?: object
}

export interface CredentialSuccess {
  format: string
  credential: string
}

export interface Siopv2Success {
  id_token: string
  client_id: string
  redirect_uri: string
  request: string
  response_mode: string
  response_type: string
  scope?: string
}

export interface VerifiablePresentationSuccess {
  request: string
  presentation_definition: PresentationDefinition
  client_id: string
  redirect_uri: string
  response_mode?: string
  response_type: string
}

export type PresentationDefinition = {
  id: string
  input_descriptors: Array<InputDescriptor>
}

export type InputDescriptor = {
  format: {
    [format: string]: Object
  }
  constraints: {
    fields: Array<{ path: Array<string> }>
  }
}
