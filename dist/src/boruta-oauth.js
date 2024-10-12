import axios from 'axios';
import { createPreauthorizedCodeClient, createClientCredentialsClient, createImplicitClient, createRevokeClient, createSiopv2Client } from './client-factories';
export class BorutaOauth {
    constructor({ host, authorizePath, tokenPath, revokePath, jwksPath, window }) {
        this.window = window;
        this.host = host;
        this.tokenPath = tokenPath;
        this.authorizePath = authorizePath;
        this.revokePath = revokePath;
        this.jwksPath = jwksPath;
    }
    get api() {
        return axios.create({
            baseURL: this.host
        });
    }
    get ClientCredentials() {
        return createClientCredentialsClient({ oauth: this });
    }
    get PreauthorizedCode() {
        return createPreauthorizedCodeClient({ oauth: this, window: this.window });
    }
    get Implicit() {
        return createImplicitClient({ oauth: this, window: this.window });
    }
    get Revoke() {
        return createRevokeClient({ oauth: this, window: this.window });
    }
    get Siopv2() {
        return createSiopv2Client({ oauth: this, window: this.window });
    }
}
