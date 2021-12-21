const https = require('https')
const http = require('http')
const crypto = require('crypto');

function BufToDER(datatype, buf) {
  let lengthSize = 0;
  let remLength = buf.length;

  if (remLength > 127) {
    lengthSize++;
    while (remLength > 127) {
      remLength >>= 8;
      lengthSize += 1;
    }
  }

  const header = Buffer.alloc(2 + lengthSize);
  header[0] = datatype;

  remLength = buf.length;
  if (remLength < 127) {
    header[1] = remLength;
  } else {
    header[1] = lengthSize | 0x80;
    const lengthArr = new Uint8Array(lengthSize);
    let i = 0;
    while (i < lengthSize) {
      lengthArr[i] = remLength % 256;
      remLength /= 256;
      i++;
    }
    lengthArr.reverse().forEach((elt, idx) => {
      header[idx + 2] = elt;
    })
  }

  return Buffer.concat([header, buf]);
};

let global_cache = {
  initialized: false,
  keys: null,
};

const parseChunk = (part) => {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
}

const loadKeys = (iss) => {
  const issuer = new URL(iss);
  return new Promise((resolve, reject) => {
    const client = issuer.protocol === 'http:' ? http : https;
    const req = client.get(`${iss}/v1/keys`, res => {
      res.on('data', d => {
        resolve(d);
      })
    })
    req.on('error', error => {
      reject(error);
    })
    req.end()
  });
}

const validateSignature = async (keys, token) => {
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new Error('malformed JWT')
  }
  const [headerPart, payloadPart, sig] = parts
  let header, payload;
  try {
    [header, payload] = [headerPart, payloadPart].map(parseChunk);
  } catch {
    throw new Error('malformed JWT')
  }
  if (header.alg !== 'RS256') { throw new Error('unsupported JWT alg'); }
  if (!header.kid || header.kid.length < 1) { throw new Error('malformed header: missing KID'); }
  const key = keys.find(elt => elt.kid == header.kid && elt.alg == header.alg);
  if (key === undefined) { throw new Error('KID ' + header.kid + ' not found'); }
  const encodedKey = ['-----BEGIN RSA PUBLIC KEY-----',
    BufToDER(
      0x30, Buffer.concat([BufToDER(0x2, Buffer.from(key.n, 'base64')), BufToDER(0x2, Buffer.from(key.e, 'base64'))])
    ).toString('base64'),
    '-----END RSA PUBLIC KEY-----',
  ].join(String.fromCharCode(10));
  const pubkey = crypto.createPublicKey(encodedKey, 'der', 'pkcs1');
  const verifyFunction = crypto.createVerify('RSA-SHA256');
  verifyFunction.write(headerPart + '.' + payloadPart);
  verifyFunction.end();

  const signatureIsValid = verifyFunction.verify(pubkey, Buffer.from(sig, 'base64url'));
  if (!signatureIsValid) {
    throw new Error('invalid JWT signature')
  }
  return payload;
}

const ensureString = (name, received, expected) => {
  if (expected !== received) {
    throw new Error('invalid ' + name + ': expected "' + expected + '" but received "' + received + '".');
  }
}
const validate = async (token, issuer, audience, scopes = []) => {
  const now = parseInt(Date.now() / 1000);
  if (global_cache.initialized === false) {
    try {
      const keys = JSON.parse(await loadKeys(issuer)).keys;
      global_cache = { keys, initialized: true };
    } catch (err) {
      throw new Error('Failed to load keys: ' + err);
    }
  }
  const claim = await validateSignature(global_cache.keys, token);
  if (claim.exp <= now || claim.iat > now) {
    throw new Error('JWT expired');
  }
  ensureString("issuer", claim.iss, issuer)
  ensureString("audience", claim.aud, audience)
  if (!scopes.every(scope => claim.scp.some(elt == scope))) {
    throw new Error('missing scope');
  }
  return claim;
}

exports.validate = validate;
