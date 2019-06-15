import { IncomingMessage, ServerResponse } from 'http';

interface XXssProtectionOptions {
  reportUri?: string;
  setOnOldIE?: boolean;
}

export = function xXssProtection (options: XXssProtectionOptions = {}) {
  let headerValue = '1; mode=block';
  if (options.reportUri) {
    headerValue += `; report=${options.reportUri}`;
  }

  if (options.setOnOldIE) {
    return function xXssProtection (_req: IncomingMessage, res: ServerResponse, next: () => void) {
      res.setHeader('X-XSS-Protection', headerValue);
      next();
    };
  } else {
    return function xXssProtection (req: IncomingMessage, res: ServerResponse, next: () => void) {
      const matches = /msie\s*(\d+)/i.exec(req.headers['user-agent'] || '');

      let value;
      if (!matches || parseFloat(matches[1]) >= 9) {
        value = headerValue;
      } else {
        value = '0';
      }

      res.setHeader('X-XSS-Protection', value);
      next();
    };
  }
}
