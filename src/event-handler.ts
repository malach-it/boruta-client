export type StoreEventType = 'insert_credential-request' |
  'insert_credential-approval' |
  'delete_credential-request' |
  'delete_credential-approval' |
  'generate_key-request' |
  'generate_key-approval' |
  'remove_key-request' |
  'remove_key-approval' |
  'extract_key-request' |
  'extract_key-approval'

export interface EventHandler {
  dispatch(type: StoreEventType, key?: string, payload?: unknown): Promise<void>
  listen(type: StoreEventType, key: string, callback: Function): Promise<void>
  remove(type: StoreEventType, key: string, callback: Function): Promise<void>
}

export class BrowserEventHandler implements EventHandler {
  window: Window

  constructor (window: Window) {
    this.window = window
  }

  async dispatch(type: StoreEventType, key: string = ''): Promise<void> {
    this.window.dispatchEvent(new Event(`${type}~${key}`))
  }

  async listen(type: StoreEventType, key: string, callback: () => void): Promise<void> {
    this.window.addEventListener(`${type}~${key}`, callback)
  }

  async remove (type: StoreEventType, key: string, callback: () => void): Promise<void> {
    this.window.removeEventListener(`${type}~${key}`, callback)
  }
}

export class CustomEventHandler implements EventHandler {
  // @ts-ignore
  events: { [key: string]: any }

  constructor () {
    this.events = {}
  }

  async dispatch (type: StoreEventType, key: string = '', payload?: unknown): Promise<void> {
    this.events[this.eventKey(type, key)] = payload || true
  }

  async listen (type: StoreEventType, key: string, callback: Function): Promise<void> {
    Object.defineProperties(this.events, {
      [this.eventKey(type, key)]: {
        set (target) {
          callback(target)
        }
      }
    })
  }

  async remove (type: StoreEventType, key: string, callback: Function): Promise<void> {
    delete this.events[this.eventKey(type, key)]
  }

  eventKey (type: StoreEventType, key: string) {
    return `${type}-${key}`
  }
}
