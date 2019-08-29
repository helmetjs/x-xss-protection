import { IncomingMessage, ServerResponse } from 'http';

interface XXssProtectionOptions {
  reportUri?: string;
  setOnOldIE?: boolean;
}

function doesUserAgentMatchOldInternetExplorer(userAgent: string | undefined): boolean {
  if (!userAgent) {
    return false;
  }

  const matches = /msie\s*(\d{1,2})/i.exec(userAgent);
  return matches ? parseFloat(matches[1]) < 9 : false;
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
      const value = doesUserAgentMatchOldInternetExplorer(req.headers['user-agent']) ? '0' : headerValue;
      res.setHeader('X-XSS-Protection', value);
      next();
    };
  }
}
