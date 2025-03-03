import axios from 'axios';
import { createPreauthorizedCodeClient, createClientCredentialsClient, createImplicitClient, createRevokeClient, createSiopv2Client, createVerifiableCredentialsIssuanceClient } from './client-factories';
export class BorutaOauth {
    constructor({ host, authorizePath, tokenPath, credentialPath, revokePath, jwksPath, window, storage }) {
        this.window = window;
        this.storage = storage;
        this.host = host;
        this.tokenPath = tokenPath;
        this.credentialPath = credentialPath;
        this.authorizePath = authorizePath;
        this.revokePath = revokePath;
        this.jwksPath = jwksPath;
    }
    get api() {
        return axios.create({
            headers: { 'Content-Type': 'application/json' },
            baseURL: this.host
        });
    }
    get ClientCredentials() {
        return createClientCredentialsClient({ oauth: this });
    }
    get VerifiableCredentialsIssuance() {
        if (!this.storage) {
            throw new Error('You must specify a storage to build this client type.');
        }
        return createVerifiableCredentialsIssuanceClient({ oauth: this, window: this.window, storage: this.storage });
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
        if (!this.storage) {
            throw new Error('You must specify a storage to build this client type.');
        }
        return createSiopv2Client({ oauth: this, window: this.window, storage: this.storage });
    }
}
