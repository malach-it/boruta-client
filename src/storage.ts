export interface Storage {
  store(key: string, value: unknown): Promise<void>
  get<T>(key: string): Promise<T | null>
}

export class BrowserStorage implements Storage{
  window: Window

  constructor (window: Window) {
    this.window = window
  }

  async store (key: string, value: unknown): Promise<void> {
    this.window.localStorage.setItem(key, JSON.stringify(value))
  }

  async get<T> (key: string): Promise<T | null> {
    return JSON.parse(
      this.window.localStorage.getItem(key) || 'null'
    )
  }
}
