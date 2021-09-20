const fs = require('fs');
const https = require('https');
const express = require('express');

const app = express();

app.get('/hello/:token', (req, res) => {
  return res.send(req.params.token);
});

https.createServer({
  cert: fs.readFileSync('ssl.crt'),
  key: fs.readFileSync('ssl.key'),
}, app).listen(8080);
