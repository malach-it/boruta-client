"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BorutaOauth = void 0;
const axios_1 = __importDefault(require("axios"));
const client_factories_1 = require("./client-factories");
class BorutaOauth {
    constructor({ host, authorizePath, tokenPath, revokePath, window }) {
        this.window = window;
        this.host = host;
        this.tokenPath = tokenPath;
        this.authorizePath = authorizePath;
        this.revokePath = revokePath;
    }
    get api() {
        return axios_1.default.create({
            baseURL: this.host
        });
    }
    get ClientCredentials() {
        return client_factories_1.createClientCredentialsClient({ oauth: this });
    }
    get PreauthorizedCode() {
        return client_factories_1.createPreauthorizedCodeClient({ oauth: this, window: this.window });
    }
    get Implicit() {
        return client_factories_1.createImplicitClient({ oauth: this, window: this.window });
    }
    get Revoke() {
        return client_factories_1.createRevokeClient({ oauth: this, window: this.window });
    }
}
exports.BorutaOauth = BorutaOauth;
