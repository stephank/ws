var http = require('http')
  , util = require('util')
  , crypto = require('crypto')
  , events = require('events')
  , Sender = require('../lib/Sender')
  , Receiver = require('../lib/Receiver');

module.exports = {
  handlers: {
    valid: validServer,
    invalidKey: invalidRequestHandler,
    closeAfterConnect: closeAfterConnectHandler
  },
  createServer: function(port, handler, cb) {
    if (handler && !cb) {
      cb = handler;
      handler = null;
    }
    var webServer = http.createServer(function (req, res) {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      res.end('okay');
    });
    var srv = new Server(webServer);
    webServer.on('upgrade', function(req, res) {
      (handler || validServer)(srv, req, res);
    });
    webServer.listen(port, '127.0.0.1', function() { cb(srv); });
  }
};

/**
 * Test strategies
 */

function validServer(server, req, res) {
  if (typeof req.headers.upgrade === 'undefined' ||
    req.headers.upgrade.toLowerCase() !== 'websocket') {
    throw new Error('invalid headers');
    return;
  }

  if (!req.headers['sec-websocket-key']) {
    res.end();
    throw new Error('websocket key is missing');
  }

  // calc key
  var key = req.headers['sec-websocket-key'];  
  var shasum = crypto.createHash('sha1');  
  shasum.update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");  
  key = shasum.digest('base64');

  res.writeHead(101, {
      'Upgrade': 'websocket'
    , 'Connection': 'Upgrade'
    , 'Sec-WebSocket-Accept': key
  });
  res.switchProtocols(function(socket) {
    server._socket = socket;
    socket.setTimeout(0);
    socket.setNoDelay(true);

    var sender = new Sender(socket);
    var receiver = new Receiver();
    receiver.on('text', function (message, flags) {
      server.emit('message', message, flags);
      sender.send(message);
    });
    receiver.on('binary', function (message, flags) {
      flags = flags || {};
      flags.binary = true;
      server.emit('message', message, flags);
      sender.send(message, {binary: true});
    });
    receiver.on('ping', function (message, flags) {
      flags = flags || {};
      server.emit('ping', message, flags);
    });
    receiver.on('pong', function (message, flags) {
      flags = flags || {};
      server.emit('pong', message, flags);
    });
    receiver.on('close', function (code, message, flags) {
      flags = flags || {};
      server.emit('close', code, message, flags);
    });
    socket.on('data', function (data) {
      receiver.add(data);
    });
    socket.on('end', function() {
      socket.end();
    });
  });
}

function invalidRequestHandler(server, req, res) {
  if (typeof req.headers.upgrade === 'undefined' ||
    req.headers.upgrade.toLowerCase() !== 'websocket') {
    throw new Error('invalid headers');
    return;
  }

  if (!req.headers['sec-websocket-key']) {
    res.end();
    throw new Error('websocket key is missing');
  }

  // calc key
  var key = req.headers['sec-websocket-key'];  
  var shasum = crypto.createHash('sha1');  
  shasum.update(key + "bogus");  
  key = shasum.digest('base64');

  res.writeHead(101, {
      'Upgrade': 'websocket'
    , 'Connection': 'Upgrade'
    , 'Sec-WebSocket-Accept': key
  });
  res.end();
}

function closeAfterConnectHandler(server, req, res) {
  if (typeof req.headers.upgrade === 'undefined' ||
    req.headers.upgrade.toLowerCase() !== 'websocket') {
    throw new Error('invalid headers');
    return;
  }

  if (!req.headers['sec-websocket-key']) {
    res.end();
    throw new Error('websocket key is missing');
  }

  // calc key
  var key = req.headers['sec-websocket-key'];  
  var shasum = crypto.createHash('sha1');  
  shasum.update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");  
  key = shasum.digest('base64');

  res.writeHead(101, {
      'Upgrade': 'websocket'
    , 'Connection': 'Upgrade'
    , 'Sec-WebSocket-Accept': key
  });
  res.end();
}

/**
 * Server object, which will do the actual emitting
 */

function Server(webServer) {
  this.webServer = webServer;
}

util.inherits(Server, events.EventEmitter);

Server.prototype.close = function() {
  this.webServer.close();
  if (this._socket) this._socket.end();
}
