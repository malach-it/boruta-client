export type StoreEventType = 'insert_credential-request' |
  'insert_credential-approval' |
  'delete_credential-request' |
  'delete_credential-approval' |
  'extract_key-request' |
  'extract_key-approval'

export interface EventHandler {
  dispatch(type: StoreEventType, key: string): Promise<void>
  listen(type: StoreEventType, key: string, callback: Function): Promise<void>
}

export class BrowserEventHandler implements EventHandler {
  window: Window

  constructor (window: Window) {
    this.window = window
  }

  async dispatch(type: StoreEventType, key: string): Promise<void> {
    this.window.dispatchEvent(new Event(`${type}~${key}`))
  }

  async listen(type: StoreEventType, key: string, callback: () => void): Promise<void> {
    this.window.addEventListener(`${type}~${key}`, callback)
  }
}
