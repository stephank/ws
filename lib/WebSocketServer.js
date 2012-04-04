/*!
 * ws: a node.js websocket client
 * Copyright(c) 2011 Einar Otto Stangvik <einaros@gmail.com>
 * MIT Licensed
 */

var util = require('util')
  , events = require('events')
  , http = require('http')
  , crypto = require('crypto')
  , url = require('url')
  , Options = require('options')
  , WebSocket = require('./WebSocket')
  , tls = require('tls')
  , url = require('url');

/**
 * WebSocket implementation
 */

function WebSocketServer(options, callback) {
  options = new Options({
    host: '127.0.0.1',
    port: null,
    server: null,
    verifyClient: null,
    path: null,
    noServer: false,
    disableHixie: false,
    clientTracking: true
  }).merge(options);
  if (!options.value.port && !options.value.server && !options.value.noServer) {
    throw new TypeError('`port` or a `server` must be provided');
  }

  var self = this;

  if (options.value.port) {
    Object.defineProperty(this, '_server', {
      configurable: true,
      value: http.createServer(function (req, res) {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end('Not implemented');
      })
    });
    this._server.listen(options.value.port, options.value.host || '127.0.0.1', callback);
    Object.defineProperty(this, '_closeServer', {
      value: function() { self._server.close(); }
    });
  }
  else if (options.value.server) {
    Object.defineProperty(this, '_server', { value: options.value.server, configurable: true });
    if (options.value.path) {
      // take note of the path, to avoid collisions when multiple websocket servers are
      // listening on the same http server
      if (this._server._webSocketPaths && options.value.server._webSocketPaths[options.value.path]) {
        throw new Error('two instances of WebSocketServer cannot listen on the same http server path');
      }
      if (typeof this._server._webSocketPaths !== 'object') {
        Object.defineProperty(this._server, '_webSocketPaths', { value: {}, configurable: true });
      }
      this._server._webSocketPaths[options.value.path] = 1;
    }
  }

  if (typeof this._server != 'undefined') {
    this._server.on('error', function(error) {
      self.emit('error', error)
    });
    this._server.on('upgrade', function(req, res) {
      self.handleUpgrade(req, res, function(client) {
        self.emit('connection', client);
      });
    });
  }

  Object.defineProperty(this, 'options', { value: options.value });
  Object.defineProperty(this, 'path', { value: options.value.path });
  Object.defineProperty(this, '_clients', { value: [] });
  Object.defineProperty(this, 'clients', {
    get: function() { return self._clients; }
  });
}

/**
 * Inherits from EventEmitter.
 */

util.inherits(WebSocketServer, events.EventEmitter);

/**
 * Immediately shuts down the connection.
 *
 * @api public
 */

WebSocketServer.prototype.close = function(code, data) {
  // terminate all associated clients
  var error = null;
  try {
    for (var i = 0, l = this._clients.length; i < l; ++i) {
      this._clients[i].terminate();
    }
  }
  catch (e) {
    error = e;
  }

  // remove path descriptor, if any
  if (this.path && this._server._webSocketPaths) {
    delete this._server._webSocketPaths[this.path];
    if (Object.keys(this._server._webSocketPaths).length == 0) {
      delete this._server._webSocketPaths;
    }
  }

  // close the http server if it was internally created
  try {
    if (typeof this._closeServer !== 'undefined') {
      this._closeServer();
    }
  }
  finally {
    delete this._server;
  }
  if (error) throw error;
}

/**
 * Handle a HTTP Upgrade request.
 *
 * @api public
 */

WebSocketServer.prototype.handleUpgrade = function(req, res, cb) {
  // check for wrong path
  if (this.options.path) {
    var u = url.parse(req.url);
    if (u && u.pathname !== this.options.path) return;
  }

  if (typeof req.headers.upgrade === 'undefined' || req.headers.upgrade.toLowerCase() !== 'websocket') {
    abortConnection(res, 400);
    return;
  }

  if (req.headers['sec-websocket-key1']) handleHixieUpgrade.apply(this, arguments);
  else handleHybiUpgrade.apply(this, arguments);
}

module.exports = WebSocketServer;

/**
 * Entirely private apis,
 * which may or may not be bound to a sepcific WebSocket instance.
 */

function handleHybiUpgrade(req, res, cb) {
  // verify key presence
  if (!req.headers['sec-websocket-key']) {
    abortConnection(res, 400);
    return;
  }

  // verify version
  var version = parseInt(req.headers['sec-websocket-version']);
  if ([8, 13].indexOf(version) === -1) {
    abortConnection(res, 400);
    return;
  }

  // verify client
  var origin = version < 13 ?
    req.headers['sec-websocket-origin'] :
    req.headers['origin'];

  var args = [req, res, version, cb];
  if (typeof this.options.verifyClient == 'function') {
    var info = {
      origin: origin,
      secure: typeof req.connection.encrypted !== 'undefined',
      req: req
    };
    if (this.options.verifyClient.length == 2) {
      var self = this;
      this.options.verifyClient(info, function(result) {
        if (!result) abortConnection(res, 401)
        else completeUpgrade.apply(self, args);
      });
      return;
    }
    else if (!this.options.verifyClient(info)) {
      abortConnection(res, 401);
      return;
    }
  }

  completeUpgrade.apply(this, args);
}

function completeUpgrade(req, res, version, cb) {
  var self = this;
  var protocol = req.headers['sec-websocket-protocol'];

  // calc key
  var key = req.headers['sec-websocket-key'];
  var shasum = crypto.createHash('sha1');
  shasum.update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  key = shasum.digest('base64');

  if (typeof protocol != 'undefined') {
    res.setHeader('Sec-WebSocket-Protocol', protocol);
  }
  res.writeHead(101, {
      'Upgrade': 'websocket'
    , 'Connection': 'Upgrade'
    , 'Sec-WebSocket-Accept': key
  });
  res.switchProtocols(function(socket) {
    socket.setTimeout(0);
    socket.setNoDelay(true);
    var client = new WebSocket([req, socket, null], {
      protocolVersion: version,
      protocol: protocol
    });

    if (self.options.clientTracking) {
      self._clients.push(client);
      client.on('close', function() {
        var index = self._clients.indexOf(client);
        if (index != -1) {
          self._clients.splice(index, 1);
        }
      });
    }
    cb(client);
  });
}

function handleHixieUpgrade(req, res, cb) {
  if (this.options.disableHixie) {
    abortConnection(res, 401, 'Hixie support disabled');
    return;
  }

  // verify key presence
  if (!req.headers['sec-websocket-key2']) {
    abortConnection(res, 400);
    return;
  }

  var self = this
    , protocol = req.headers['sec-websocket-protocol']
    , secure = typeof req.connection.encrypted !== 'undefined'
    , scheme = ((secure || req.headers['x-forwarded-proto'] === 'https') ? 'wss' : 'ws')
    , location = scheme + '://' + req.headers.host + req.url
    , origin = req.headers['origin']
    , md5 = crypto.createHash('md5');

  // verify client
  if (typeof this.options.verifyClient == 'function') {
    var info = {
        origin: origin
      , secure: secure
      , req: req
    };
    if (this.options.verifyClient.length == 2)
      this.options.verifyClient(info, verifyCallback);
    else
      verifyCallback(this.options.verifyClient(info));
  }
  else {
    verifyCallback(true);
  }
  function verifyCallback(result) {
    if (!result) {
      abortConnection(res, 401);
      return;
    }

    // calculate key
    var abort = false
      , k1 = req.headers['sec-websocket-key1']
      , k2 = req.headers['sec-websocket-key2']
      , md5 = crypto.createHash('md5');
    [k1, k2].forEach(function (k) {
      var n = parseInt(k.replace(/[^\d]/g, ''))
        , spaces = k.replace(/[^ ]/g, '').length;
      if (spaces === 0 || n % spaces !== 0) {
        abort = true;
        return;
      }
      n /= spaces;
      md5.update(String.fromCharCode(
          n >> 24 & 0xFF
        , n >> 16 & 0xFF
        , n >> 8  & 0xFF
        , n       & 0xFF
      ));
    });
    if (abort) {
      abortConnection(res, 400);
      return;
    }

    // write headers, get a hold of the socket
    if (typeof protocol != 'undefined') res.setHeader('Sec-WebSocket-Protocol', protocol);
    if (typeof origin != 'undefined') res.setHeader('Sec-WebSocket-Origin', origin);
    res.writeHead(101, {
        'Upgrade': 'WebSocket'
      , 'Connection': 'Upgrade'
      , 'Sec-WebSocket-Location': location
    });
    res.switchProtocols(switchCallback);
  }

  function switchCallback(socket) {
    socket.setTimeout(0);
    socket.setNoDelay(true);

    // retrieve nonce
    var remaining = 8;
    socket.addListener('data', function nonceHandler(data) {
      var toRead = Math.min(data.length, remaining);
      md5.update(data.slice(0, toRead));

      if (toRead === remaining) {
        var rest = data.slice(toRead);
        socket.removeListener('data', nonceHandler);
        completeHandshake(socket, rest);
      }
      else {
        remaining -= toRead;
      }
    });
  }

  // handshake completion code to run once nonce has been successfully retrieved
  function completeHandshake(socket, rest) {
    try {
      socket.write(md5.digest('binary'), 'binary');
    }
    catch (e) {
      try { socket.end(); } catch (_) {}
      return;
    }

    var client = new WebSocket([req, socket, rest], {
      protocolVersion: 'hixie-76',
      protocol: protocol
    });
    if (self.options.clientTracking) {
      self._clients.push(client);
      client.on('close', function() {
        var index = self._clients.indexOf(client);
        if (index != -1) {
          self._clients.splice(index, 1);
        }
      });
    }
    cb(client);
  }
}

function abortConnection(res, code, name) {
  var headers = {
      'Content-Type': 'text/plain'
    , 'Content-Length': 0
  };
  if (name)
    res.writeHead(code, name, headers);
  else
    res.writeHead(code, headers);
  res.end();
}
