import { IncomingMessage, ServerResponse } from 'http';

interface XXssProtectionOptions {
  mode?: 'block' | null;
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

function getHeaderValueFromOptions (options: XXssProtectionOptions): string {
  const directives: string[] = ['1'];

  let isBlockMode: boolean;
  if ('mode' in options) {
    if (options.mode === 'block') {
      isBlockMode = true;
    } else if (options.mode === null) {
      isBlockMode = false;
    } else {
      throw new Error('The `mode` option must be set to "block" or null.');
    }
  } else {
    isBlockMode = true;
  }

  if (isBlockMode) {
    directives.push('mode=block');
  }

  if (options.reportUri) {
    directives.push(`report=${options.reportUri}`);
  }

  return directives.join('; ');
}

export = function xXssProtection (options: XXssProtectionOptions = {}) {
  const headerValue = getHeaderValueFromOptions(options);

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
