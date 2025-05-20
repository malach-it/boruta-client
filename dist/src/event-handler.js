var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
export class BrowserEventHandler {
    constructor(window) {
        this.window = window;
    }
    dispatch(type_1) {
        return __awaiter(this, arguments, void 0, function* (type, key = '') {
            this.window.dispatchEvent(new Event(`${type}~${key}`));
        });
    }
    listen(type, key, callback) {
        return __awaiter(this, void 0, void 0, function* () {
            this.window.addEventListener(`${type}~${key}`, callback);
        });
    }
    remove(type, key, callback) {
        return __awaiter(this, void 0, void 0, function* () {
            this.window.removeEventListener(`${type}~${key}`, callback);
        });
    }
}
export class CustomEventHandler {
    constructor() {
        this.events = {};
    }
    dispatch(type_1) {
        return __awaiter(this, arguments, void 0, function* (type, key = '', payload) {
            this.events[this.eventKey(type, key)] = payload || true;
        });
    }
    listen(type, key, callback) {
        return __awaiter(this, void 0, void 0, function* () {
            Object.defineProperties(this.events, {
                [this.eventKey(type, key)]: {
                    set(target) {
                        callback(target);
                    }
                }
            });
        });
    }
    remove(type, key, callback) {
        return __awaiter(this, void 0, void 0, function* () {
            delete this.events[this.eventKey(type, key)];
        });
    }
    eventKey(type, key) {
        return `${type}-${key}`;
    }
}
