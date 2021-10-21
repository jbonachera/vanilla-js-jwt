const crypto = require('crypto');
const http = require('http');
const validate = require('./index').validate;

const createJWT = (privateKey, { header, sub, iat, exp, iss, aud } = {}) => {
  const now = parseInt(Date.now() / 1000);
  const header_data = JSON.stringify(header ? header : {
    "alg": "RS256",
    "kid": "1",
  });
  const payload_data = JSON.stringify({
    "sub": sub ? sub : "sub",
    "iat": iat ? iat : now - 60,
    "exp": exp ? exp : now + 60,
    "iss": iss ? iss : "http://127.0.0.1:8080",
    "aud": aud ? aud : "api://localhost"
  });
  const data = Buffer.from(`${Buffer.from(header_data).toString('base64url')}.${Buffer.from(payload_data).toString('base64url')}`);
  return `${data}.${crypto.sign("SHA256", data, privateKey).toString('base64url')}`
};


let server;
let publicKey;
let privateKey;

beforeAll((done) => {
  const out = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'jwk'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    }
  });
  publicKey = out.publicKey;
  privateKey = out.privateKey;
  server = http.createServer((req, res) => {
    res
      .writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({
        "keys": [{ kid: "1", alg: 'RS256', use: 'sig', ...publicKey }]
      }));
  }).listen({ port: 8080, host: '127.0.0.1' }, done);
});

afterAll(() => { server.close() });

describe('Validate()', () => {
  it('should accept a valid JWT', async () => {
    const token = createJWT(privateKey, { sub: "good" });
    await expect(validate(token, 'http://127.0.0.1:8080', 'api://localhost')).resolves.toMatchObject({ "sub": "good" })
  });
  it('should reject a not-valid-yet JWT', async () => {
    const token = createJWT(privateKey, { iat: Date.now() + 50 });
    await expect(validate(token, 'http://127.0.0.1:8080', 'api://localhost')).rejects.toEqual(new Error("JWT expired"));
  });
  it('should reject an expired JWT', async () => {
    const token = createJWT(privateKey, { exp: 1 });
    await expect(validate(token, 'http://127.0.0.1:8080', 'api://localhost')).rejects.toEqual(new Error("JWT expired"));
  });
  it('should reject a corrupted JWT', async () => {
    let token = createJWT(privateKey);
    await expect(validate('token' + "_", 'http://127.0.0.1:8080', 'api://localhost')).rejects.toEqual(new Error("malformed JWT"));
    await expect(validate('token.token.token' + "_", 'http://127.0.0.1:8080', 'api://localhost')).rejects.toEqual(new Error("malformed JWT"));
    await expect(validate(token + "_", 'http://127.0.0.1:8080', 'api://localhost')).rejects.toEqual(new Error("invalid JWT signature"));
  });
  it('should reject an edited JWT', async () => {
    let token = createJWT(privateKey);
    let fakeToken = `${token.split('.')[0]}.${Buffer.from(JSON.stringify({ "sub": "sub" })).toString("base64url")}.${token.split('.')[2]}`
    await expect(validate(fakeToken, 'http://127.0.0.1:8080', 'api://localhost')).rejects.toEqual(new Error("invalid JWT signature"));
  });
  it('should reject a JWT with wrong audience', async () => {
    let token = createJWT(privateKey);
    await expect(validate(token, 'http://127.0.0.1:8080', 'api://audience')).rejects.toEqual(new Error(`invalid audience: expected "api://audience" but received "api://localhost".`));
  });
  it('should reject a JWT with wrong issuer', async () => {
    let token = createJWT(privateKey, { iss: 'http://example.net' });
    await expect(validate(token, 'http://127.0.0.1:8080', 'api://audience')).rejects.toEqual(new Error(`invalid issuer: expected "http://127.0.0.1:8080" but received "http://example.net".`));
  });
  it('should reject a JWT with no Key ID', async () => {
    let token = createJWT(privateKey, { header: { alg: 'RS256' } });
    await expect(validate(token, 'http://127.0.0.1:8080', 'api://audience')).rejects.toEqual(new Error(`malformed header: missing KID`));
  });
  it('should reject a JWT with an unknown Key ID', async () => {
    let token = createJWT(privateKey, { header: { alg: 'RS256', kid: '2' } });
    await expect(validate(token, 'http://127.0.0.1:8080', 'api://audience')).rejects.toEqual(new Error(`KID 2 not found`));
  });
  it('should reject a JWT with unsupported key algorithm', async () => {
    let token = createJWT(privateKey, { header: { alg: 'RS512' } });
    await expect(validate(token, 'http://127.0.0.1:8080', 'api://audience')).rejects.toEqual(new Error(`unsupported JWT alg`));
  });
});