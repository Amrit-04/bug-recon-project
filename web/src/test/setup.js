import '@testing-library/jest-dom';

// Polyfill EventSource for jsdom environment in tests
if (typeof global.EventSource === 'undefined') {
  global.EventSource = class MockEventSource {
    constructor(url) {
      this.url = url;
      this.listeners = {};
    }
    addEventListener(event, callback) {
      this.listeners[event] = callback;
    }
    removeEventListener(event) {
      delete this.listeners[event];
    }
    close() {}
  };
}
