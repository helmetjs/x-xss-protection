import connect from 'connect';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { IncomingMessage, ServerResponse } from 'http';

import xssFilter = require('..');

describe('x-xss-protection', () => {
  let enabledBrowsers: string[] = [];
  let disabledBrowsers: string[] = [];

  beforeAll(() => {
    function grabList (filename: string) {
      const filepath = path.join(__dirname, filename);
      return fs.readFileSync(filepath, { encoding: 'utf8' })
        .split('\n')
        .filter(line => line.trim());
    }

    enabledBrowsers = grabList('enabled_browser_list.txt');
    disabledBrowsers = grabList('disabled_browser_list.txt');
  });

  function app(middleware: ReturnType<typeof xssFilter>) {
    const result = connect();
    result.use(middleware);
    result.use((_req: IncomingMessage, res: ServerResponse) => {
      res.end('Hello world!');
    });
    return result;
  }

  it('enables it for supported browsers', () => {
    const testApp = app(xssFilter());
    return Promise.all(enabledBrowsers.map((useragent) => {
      return request(testApp)
        .get('/')
        .set('User-Agent', useragent)
        .expect('X-XSS-Protection', '1; mode=block');
    }));
  });

  it('disables it for unsupported browsers', () => {
    const testApp = app(xssFilter());
    return Promise.all(disabledBrowsers.map((useragent) => {
      return request(testApp)
        .get('/')
        .set('User-Agent', useragent)
        .expect('X-XSS-Protection', '0');
    }));
  });

  it('sets header if there is an empty user-agent', () => {
    return request(app(xssFilter()))
      .get('/')
      .set('User-Agent', '')
      .expect('X-XSS-Protection', '1; mode=block');
  });

  it('sets header if there is no user-agent', () => {
    return request(app(xssFilter()))
      .get('/')
      .unset('User-Agent')
      .expect('X-XSS-Protection', '1; mode=block');
  });

  it('allows you to force the header for unsupported browsers', () => {
    const testApp = app(xssFilter({ setOnOldIE: true }));
    return Promise.all(disabledBrowsers.map((useragent) => {
      return request(testApp)
        .get('/')
        .set('User-Agent', useragent)
        .expect('X-XSS-Protection', '1; mode=block');
    }));
  });

  it('uses a reporting URI if specified', () => {
    const testApp = app(xssFilter({ reportUri: '/report-path' }));
    return Promise.all(enabledBrowsers.map((useragent) => {
      return request(testApp)
        .get('/')
        .set('User-Agent', useragent)
        .expect('X-XSS-Protection', '1; mode=block; report=/report-path');
    }));
  });

  it('allows you to set the mode to "block", which is the default', () => {
    const testApp = app(xssFilter({ mode: 'block' }));
    return request(testApp)
      .get('/')
      .expect('X-XSS-Protection', '1; mode=block');
  });

  it('allows you to set the mode to null, disabling mode=block', () => {
    const testApp = app(xssFilter({ mode: null }));
    return request(testApp)
      .get('/')
      .expect('X-XSS-Protection', '1');
  });

  it('errors if the mode is anything other than "block" or null', () => {
    /* eslint-disable @typescript-eslint/no-explicit-any */
    expect(xssFilter.bind(null, { mode: undefined } as any)).toThrow();
    expect(xssFilter.bind(null, { mode: 'BLOCK' } as any)).toThrow();
    expect(xssFilter.bind(null, { mode: new String('block') } as any)).toThrow(); // eslint-disable-line no-new-wrappers
    expect(xssFilter.bind(null, { mode: 123 } as any)).toThrow();
    /* eslint-enable @typescript-eslint/no-explicit-any */
  });

  it('names its function and middleware', () => {
    expect(xssFilter.name).toStrictEqual('xXssProtection');
    expect(xssFilter().name).toStrictEqual('xXssProtection');
  });
});
