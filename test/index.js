var xssFilter = require('..')

var connect = require('connect')
var request = require('supertest')
var rfile = require('rfile')
var each = require('async/each')
var assert = require('assert')

describe('x-xss-protection', function () {
  before(function () {
    function grabList (filename) {
      return rfile(filename)
        .split('\n')
        .filter(function (line) {
          return line.trim() !== ''
        })
    }

    this.enabledBrowsers = grabList('./enabled_browser_list.txt')
    this.disabledBrowsers = grabList('./disabled_browser_list.txt')
  })

  beforeEach(function () {
    this.app = connect()
    this.app.use(xssFilter())
    this.app.use(function (req, res) {
      res.end('Hello world!')
    })
  })

  it('enables it for supported browsers', function (done) {
    each(this.enabledBrowsers, function (useragent, callback) {
      request(this.app).get('/').set('User-Agent', useragent)
        .expect('X-XSS-Protection', '1; mode=block', callback)
    }.bind(this), done)
  })

  it('disables it for unsupported browsers', function (done) {
    each(this.disabledBrowsers, function (useragent, callback) {
      request(this.app).get('/').set('User-Agent', useragent)
        .expect('X-XSS-Protection', '0', callback)
    }.bind(this), done)
  })

  it('sets header if there is an empty user-agent', function (done) {
    request(this.app).get('/').set('User-Agent', '')
      .expect('X-XSS-Protection', '1; mode=block', done)
  })

  it('sets header if there is no user-agent', function (done) {
    request(this.app).get('/').unset('User-Agent')
      .expect('X-XSS-Protection', '1; mode=block', done)
  })

  it('allows you to force the header for unsupported browsers', function (done) {
    var app = connect()
    app.use(xssFilter({ setOnOldIE: true }))
    app.use(function (req, res) {
      res.end('Hello world!')
    })

    each(this.disabledBrowsers, function (useragent, callback) {
      request(app).get('/').set('User-Agent', useragent)
        .expect('X-XSS-Protection', '1; mode=block', callback)
    }, done)
  })

  it('names its function and middleware', function () {
    assert.equal(xssFilter.name, 'xXssProtection')
    assert.equal(xssFilter().name, 'xXssProtection')
  })
})
