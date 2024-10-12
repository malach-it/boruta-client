var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { OauthError } from "../oauth-responses";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { SignJWT, exportJWK, importJWK, generateKeyPair } from "jose";
const PUBLIC_KEY_STORAGE_KEY = 'wallet_public_key';
const PRIVATE_KEY_STORAGE_KEY = 'wallet_private_key';
export function createSiopv2Client({ oauth, window }) {
    return class Siopv2 {
        constructor() {
            this.oauth = oauth;
        }
        parseSiopv2Response(location) {
            return __awaiter(this, void 0, void 0, function* () {
                if (location.search === '') {
                    return Promise.reject(new OauthError({
                        error: 'unkown_error',
                        error_description: 'Siopv2 response location must contain query params.'
                    }));
                }
                const params = new URLSearchParams(location.search);
                const { client_id, redirect_uri, request, response_mode, response_type, scope } = yield parseSiopv2Params(params);
                if (!oauth.jwksPath) {
                    return Promise.reject(new OauthError({
                        error: 'unkown_error',
                        error_description: 'You must provide server jwks path.'
                    }));
                }
                // TODO verify request signature
                // await oauth.api.get<jwksResponse>(oauth.jwksPath).then(({ data }) => {
                //   const keys = data.keys
                //   let jwt
                //   while (true) {
                //     const key = keys.pop()
                //     if (!key) {
                //       throw new OauthError({
                //         error: 'unknown_error',
                //         error_description: 'Request signature could not be verified.'
                //       })
                //     }
                //     console.log(request)
                //     console.log(key)
                //     jwt = verify(request, key, (err, decoded) => console.log(decoded))
                //     console.log(jwt)
                //   }
                // })
                const { privateKey, did } = yield extractKeys();
                const now = Math.floor((new Date()) / 1000);
                const payload = {
                    "iss": did,
                    "sub": did,
                    "aud": redirect_uri,
                    "nonce": "nonce",
                    "exp": now + 600,
                    "iat": now
                };
                const id_token = yield new SignJWT(payload)
                    .setProtectedHeader({ alg: 'ES256', kid: did })
                    .sign(privateKey);
                return {
                    id_token,
                    client_id,
                    redirect_uri,
                    request,
                    response_mode,
                    response_type,
                    scope
                };
            });
        }
    };
}
function parseSiopv2Params(params) {
    const client_id = params.get('client_id');
    if (!client_id) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'client_id parameter is missing in Siopv2 response location.'
        }));
    }
    const redirect_uri = params.get('redirect_uri');
    if (!redirect_uri) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'redirect_uri parameter is missing in Siopv2 response location.'
        }));
    }
    const request = params.get('request');
    if (!request) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'request parameter is missing in Siopv2 response location.'
        }));
    }
    const response_mode = params.get('response_mode');
    if (!response_mode) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'response_mode parameter is missing in Siopv2 response location.'
        }));
    }
    const response_type = params.get('response_type');
    if (!response_type) {
        return Promise.reject(new OauthError({
            error: 'unkown_error',
            error_description: 'response_type parameter is missing in Siopv2 response location.'
        }));
    }
    const scope = params.get('scope') || undefined;
    return Promise.resolve({
        id_token: '',
        client_id,
        redirect_uri,
        request,
        response_mode,
        response_type,
        scope
    });
}
function extractKeys() {
    return __awaiter(this, void 0, void 0, function* () {
        let publicKeyJwk, publicKey, privateKey;
        if (window.localStorage.getItem(PUBLIC_KEY_STORAGE_KEY) && window.localStorage.getItem(PRIVATE_KEY_STORAGE_KEY)) {
            publicKeyJwk = JSON.parse(window.localStorage.getItem(PUBLIC_KEY_STORAGE_KEY));
            publicKey = yield importJWK(publicKeyJwk, 'ES256');
            privateKey = yield importJWK(JSON.parse(window.localStorage.getItem(PRIVATE_KEY_STORAGE_KEY)), 'ES256');
        }
        else {
            const { privateKey, publicKey } = yield generateKeyPair("ES256", { extractable: true });
            publicKeyJwk = yield exportJWK(publicKey);
            window.localStorage.setItem(PUBLIC_KEY_STORAGE_KEY, JSON.stringify(publicKeyJwk));
            window.localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, JSON.stringify(yield exportJWK(privateKey)));
        }
        const did = EbsiWallet.createDid("NATURAL_PERSON", publicKeyJwk);
        return { publicKey, privateKey, did };
    });
}
