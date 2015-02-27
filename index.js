module.exports = function(options) {

  options = options || {};

  if (options.setOnOldIE) {

    return function(req, res, next) {
      res.setHeader('X-XSS-Protection', '1; mode=block');
      next();
    };

  } else {

    return function(req, res, next)  {

      var ua = req.headers['user-agent'] || '';
      var matches = ua.match(/msie\s*(\d+)/i);

      var value;
      if (!matches || (parseFloat(matches[1]) >= 9)) {
        value = '1; mode=block';
      } else {
        value = '0';
      }

      res.setHeader('X-XSS-Protection', value);
      next();

    };

  }


};
