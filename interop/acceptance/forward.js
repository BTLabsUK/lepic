// SPDX-License-Identifier: Apache-2.0
// Forwards TCP ports for the acceptance gateway: `node forward.js <listen>=<host>:<port> ...`.
// It listens on each of the container's own IPv4 interface addresses, never on a wildcard, so
// that what it exposes is exactly the networks the container is attached to.
'use strict';

const net = require('net');
const os = require('os');

const addresses = Object.values(os.networkInterfaces())
  .flat()
  .filter((entry) => entry.family === 'IPv4' && !entry.internal)
  .map((entry) => entry.address);
if (addresses.length === 0) {
  console.error('forward: no interface address to listen on');
  process.exit(1);
}

for (const rule of process.argv.slice(2)) {
  const match = /^(\d+)=([^:]+):(\d+)$/.exec(rule);
  if (!match) {
    console.error(`forward: bad rule ${rule}`);
    process.exit(2);
  }
  const [, listen, host, port] = match;
  for (const address of addresses) {
    net
      .createServer((client) => {
        const upstream = net.connect(Number(port), host);
        const close = () => {
          client.destroy();
          upstream.destroy();
        };
        client.on('error', close);
        upstream.on('error', close);
        client.pipe(upstream).pipe(client);
      })
      .on('error', (error) => {
        console.error(`forward: ${address}:${listen}: ${error.message}`);
        process.exit(1);
      })
      .listen(Number(listen), address, () => console.log(`forward: ${address}:${listen} -> ${host}:${port}`));
  }
}
