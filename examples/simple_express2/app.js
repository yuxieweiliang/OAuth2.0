// simple server with a protected resource at /secret secured by OAuth 2

var OAuth2Provider = require('../../index').OAuth2Provider,
           express = require('express'),
       MemoryStore = express.session.MemoryStore;

// hardcoded list of <client id, client secret> tuples
// 客户端ID、客户端机密>元组的硬编码列表
var myClients = {
 '1': '1secret'
};

// temporary grant storage
var myGrants = {};

var myOAP = new OAuth2Provider({
  crypt_key: 'encryption secret', // 密钥
  sign_key: 'signing secret' // 签名
});

/**
 * 在显示授权页之前，请确保用户已登录。
 */
myOAP.on('enforce_login', function(req, res, authorize_url, next) {
  console.log('enforce_login', req, res, authorize_url)
  if(req.session.user) {
    next(req.session.user);
  } else {
    res.writeHead(303, {Location: '/login?next=' + encodeURIComponent(authorize_url)});
    res.end();
  }
});

/**
 * 提供选择授权或拒绝页面。
 * 使用两个提交按钮名为“允许”和“拒绝”以供用户选择
 */
myOAP.on('authorize_form', function(req, res, client_id, authorize_url) {
  console.log('authorize_form', req, res, client_id, authorize_url)
  res.end('<html>this app wants to access your account... ' +
    '<form method="post" action="' + authorize_url + '">' +
    '<button name="allow">Allow</button>' +
    '<button name="deny">Deny</button>' +
    '</form>');
});

/**
 * 为当前用户保存生成的授权代码
 */
myOAP.on('save_grant', function(req, client_id, code, next) {
  // console.log('save_grant', req, client_id, code)
  if(!(req.session.user in myGrants))
    myGrants[req.session.user] = {};

  myGrants[req.session.user][client_id] = code;
  next();
});

/**
 * 当访问令牌已被发送时移除授权
 */
myOAP.on('remove_grant', function(user_id, client_id, code) {
  // console.log('remove_grant', user_id, client_id, code)
  if(myGrants[user_id] && myGrants[user_id][client_id])
    delete myGrants[user_id][client_id];
});

/**
 * 找到授权用户
 */
myOAP.on('lookup_grant', function(client_id, client_secret, code, next) {
  // console.log('lookup_grant', client_id, client_secret, code)
  // verify that client id/secret pair are valid
  if(client_id in myClients && myClients[client_id] == client_secret) {
    for(var user in myGrants) {
      var clients = myGrants[user];

      if(clients[client_id] && clients[client_id] == code)
        return next(null, user);
    }
  }

  next(new Error('no such grant found'));
});

/**
 * 在生成的访问令牌中嵌入不透明值
 */
myOAP.on('create_access_token', function(user_id, client_id, next) {
  // console.log('create_access_token', client_id, client_id)
  var extra_data = 'blah'; // can be any data type or null
  //var oauth_params = {token_type: 'bearer'};

  next(extra_data/*, oauth_params*/);
});

// (optional) do something with the generated access token
myOAP.on('save_access_token', function(user_id, client_id, access_token) {
  // console.log('save_access_token', client_id, client_id, access_token)
  console.log('saving access token %s for user_id=%s client_id=%s', JSON.stringify(access_token), user_id, client_id);
});

// 在URL查询字符串参数或HTTP报头中接收访问令牌。
myOAP.on('access_token', function(req, token, next) {
  var TOKEN_TTL = 10 * 60 * 1000; // 10 minutes
  // console.log('save_access_token', req, token)

  if(token.grant_date.getTime() + TOKEN_TTL > Date.now()) {
    req.session.user = token.user_id;
    req.session.data = token.extra_data;
  } else {
    console.warn('access token for user %s has expired', token.user_id);
  }

  next();
});

function router(app) {
  app.get('/', function(req, res, next) {
    // console.log('/', req.session)

    res.end('home, logged in? ' + !!req.session.user);
  });

  app.get('/login', function(req, res, next) {
    // console.log('get/login', req.session)
    if(req.session.user) {
      res.writeHead(303, {Location: '/'});
      return res.end();
    }

    // console.log(req.body)
    var next_url = req.query.next ? req.query.next : '/';

    res.end('<html>' +
      '<form method="post" action="/login">' +
      '<input type="hidden" name="next" value="' + next_url + '">' +
      '<input type="text" placeholder="username" name="username">' +
      '<input type="password" placeholder="password" name="password">' +
      '<button type="submit">Login</button>' +
      '</form>');
  });

  app.post('/login', function(req, res, next) {
    req.session.user = req.body.username;
    myOAP.emit('create_access_token', req.body.username, req.body.password, function(code) {
      console.log(code)
    })
    // console.log('post/login', req.body)
    res.writeHead(303, {Location: req.body.next || '/'});
    res.end();
  });

  app.get('/logout', function(req, res, next) {
    req.session.destroy(function(err) {
      res.writeHead(303, {Location: '/'});
      res.end();
    });
  });

  app.get('/secret', function(req, res, next) {
    if(req.session.user) {
      res.end('proceed to secret lair, extra data: ' + JSON.stringify(req.session.data));
    } else {
      res.writeHead(403);
      res.end('no');
    }
  });
}

express.createServer(
  express.logger('dev'),
  express.bodyParser(),
  express.query(),
  express.cookieParser(),
  express.session({store: new MemoryStore({reapInterval: 5 * 60 * 1000}), secret: 'abracadabra'}),
  myOAP.oauth(),
  myOAP.login(),
  express.router(router)
).listen(8082);

function escape_entities(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

