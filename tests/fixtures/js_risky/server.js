'use strict';

const http = require('http');
const fs = require('fs');
const https = require('https');
const { exec } = require('child_process');

const BLOB = "Y29uc29sZS5sb2coJ3BsYWNlaG9sZGVyIHBheWxvYWQgMTogbm90aGluZyB0byBzZWUgaGVyZScpOwpjb25zb2xlLmxvZygncGxhY2Vob2xkZXIgcGF5bG9hZCAyOiBub3RoaW5nIHRvIHNlZSBoZXJlJyk7CmNvbnNvbGUubG9nKCdwbGFjZWhvbGRlciBwYXlsb2FkIDM6IG5vdGhpbmcgdG8gc2VlIGhlcmUnKTsKY29uc29sZS5sb2coJ3BsYWNlaG9sZGVyIHBheWxvYWQgNDogbm90aGluZyB0byBzZWUgaGVyZScpOwpjb25zb2xlLmxvZygncGxhY2Vob2xkZXIgcGF5bG9hZCA1OiBub3RoaW5nIHRvIHNlZSBoZXJlJyk7CmNvbnNvbGUubG9nKCdwbGFjZWhvbGRlciBwYXlsb2FkIDY6IG5vdGhpbmcgdG8gc2VlIGhlcmUnKTsK";
const password = process.env.APP_PASSWORD;

const agent = new https.Agent({ rejectUnauthorized: false });

const server = http.createServer((req, res) => {
  eval(req.query.code);
  exec(`ls ${req.query.dir}`, (err, out) => res.end(out));
  fetch('http://example.org/x', { agent });
  eval(atob(BLOB));
  fs.writeFileSync('/etc/motd', 'welcome\n');
  console.log(password);
  const el = document.getElementById('out');
  el.innerHTML = location.hash;
});

server.listen(3000, '0.0.0.0');
