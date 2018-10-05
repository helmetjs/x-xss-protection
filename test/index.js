var xssFilter = require('..')

var connect = require('connect')
var request = require('supertest')
var fs = require('fs')
var path = require('path')
var assert = require('assert')

describe('x-xss-protection', function () {
  before(function () {
    function grabList (filename) {
      var filepath = path.join(__dirname, filename)
      return fs.readFileSync(filepath, { encoding: 'utf8' })
        .split('\n')
        .filter(function (line) {
          return line.trim()
        })
    }

    this.enabledBrowsers = grabList('enabled_browser_list.txt')
    this.disabledBrowsers = grabList('disabled_browser_list.txt')
  })

  beforeEach(function () {
    this.app = connect()
    this.app.use(xssFilter())
    this.app.use(function (req, res) {
      res.end('Hello world!')
    })
  })

  it('enables it for supported browsers', function () {
    return Promise.all(this.enabledBrowsers.map(function (useragent) {
      return request(this.app)
        .get('/')
        .set('User-Agent', useragent)
        .expect('X-XSS-Protection', '1; mode=block')
    }.bind(this)))
  })

  it('disables it for unsupported browsers', function () {
    return Promise.all(this.disabledBrowsers.map(function (useragent) {
      return request(this.app)
        .get('/')
        .set('User-Agent', useragent)
        .expect('X-XSS-Protection', '0')
    }.bind(this)))
  })

  it('sets header if there is an empty user-agent', function () {
    return request(this.app)
      .get('/')
      .set('User-Agent', '')
      .expect('X-XSS-Protection', '1; mode=block')
  })

  it('sets header if there is no user-agent', function () {
    return request(this.app)
      .get('/')
      .unset('User-Agent')
      .expect('X-XSS-Protection', '1; mode=block')
  })

  it('allows you to force the header for unsupported browsers', function () {
    var app = connect()
    app.use(xssFilter({ setOnOldIE: true }))
    app.use(function (req, res) {
      res.end('Hello world!')
    })

    return Promise.all(this.disabledBrowsers.map(function (useragent) {
      return request(app)
        .get('/')
        .set('User-Agent', useragent)
        .expect('X-XSS-Protection', '1; mode=block')
    }))
  })

  it('uses a reporting URI if specified', function () {
    var app = connect()
    app.use(xssFilter({ reportUri: '/report-path' }))
    app.use(function (req, res) {
      res.end('Hello world!')
    })

    return Promise.all(this.enabledBrowsers.map(function (useragent) {
      return request(app)
        .get('/')
        .set('User-Agent', useragent)
        .expect('X-XSS-Protection', '1; mode=block; report=/report-path')
    }))
  })

  it('names its function and middleware', function () {
    assert.strictEqual(xssFilter.name, 'xXssProtection')
    assert.strictEqual(xssFilter().name, 'xXssProtection')
  })
})
