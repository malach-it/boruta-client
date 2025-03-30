![logo-yellow](images/logo-yellow.png)

boruta client is an OAuth 2.0 client written in JavaScript/Typescript. It allows to interact with an OAuth 2.0 provider within javascript applications both on client and server sides.

## Implementation

This library gives the ability to follow the OAuth 2.0 flows. Here is the current state of what is implemented.

- [x] client credentials
- [x] implicit grant
  - [x] silent refresh impementation
- [ ] code grant
- [ ] resource owner password credentials grant
- [ ] introspect
- [x] revoke
- [x] OpenID for Verifiable Credentials Issuance
- [x] OpenID for Verifiable Presentations

## Installation

Installation can be performed with npm package manager from this repository (the code is to be released on the npm registry).

```
npm i https://github.com/malach-it/boruta-client.git
```

## Usage

### Client credentials

You have the ability to get tokens following the OAuth 2.0 client credentials flow as in the following example:

```javascript
import { BorutaOauth } from 'boruta-client'

const oauth = new BorutaOauth({
  host: 'https://oauth.provider',
  tokenPath: '/oauth/token'
})

const client = new oauth.ClientCredentials({
  clientId: 'shinyClientId',
  clientSecret: 'shinyClientSecret'
})

client.getToken().then(console.log)
```

## Code of Conduct

This product community follows the code of conduct available [here](https://io.malach.it/code-of-conduct.html)

## License

This code is released under the [MIT](LICENSE.md) license.
