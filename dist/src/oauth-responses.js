"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OauthError = void 0;
class OauthError extends Error {
    constructor({ status, error, error_description }) {
        super();
        this.status = status;
        this.error = error;
        this.error_description = error_description;
    }
    get message() {
        return this.error_description || 'An unknown error occured.';
    }
}
exports.OauthError = OauthError;
