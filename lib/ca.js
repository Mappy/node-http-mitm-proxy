var FS = require('fs');
var Forge = require('node-forge');
var pki = Forge.pki;

var CAattrs = [{
  name: 'commonName',
  value: 'NodeMITMProxyCA'
}, {
  name: 'countryName',
  value: 'Internet'
}, {
  shortName: 'ST',
  value: 'Internet'
}, {
  name: 'localityName',
  value: 'Internet'
}, {
  name: 'organizationName',
  value: 'Node MITM Proxy CA'
}, {
  shortName: 'OU',
  value: 'CA'
}];

var CAextensions = [{
  name: 'basicConstraints',
  cA: true
}, {
  name: 'keyUsage',
  keyCertSign: true,
  digitalSignature: true,
  nonRepudiation: true,
  keyEncipherment: true,
  dataEncipherment: true
}, {
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: true,
  emailProtection: true,
  timeStamping: true
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: true,
  objsign: true,
  sslCA: true,
  emailCA: true,
  objCA: true
}, {
  name: 'subjectAltName',
  altNames: [{
    type: 6, // URI
    value: 'http://example.org/webid#me'
  }, {
    type: 7, // IP
    ip: '127.0.0.1'
  }]
}, {
  name: 'subjectKeyIdentifier'
}];

var ServerAttrs = [{
  name: 'countryName',
  value: 'Internet'
}, {
  shortName: 'ST',
  value: 'Internet'
}, {
  name: 'localityName',
  value: 'Internet'
}, {
  name: 'organizationName',
  value: 'Node MITM Proxy CA'
}, {
  shortName: 'OU',
  value: 'Node MITM Proxy Server Certificate'
}];

var ServerExtensions = [{
  name: 'basicConstraints',
  cA: false
}, {
  name: 'keyUsage',
  keyCertSign: false,
  digitalSignature: true,
  nonRepudiation: false,
  keyEncipherment: true,
  dataEncipherment: true
}, {
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: false,
  emailProtection: false,
  timeStamping: false
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: false,
  objsign: false,
  sslCA: false,
  emailCA: false,
  objCA: false
}, {
  name: 'subjectKeyIdentifier'
}];

var CA = function (caFolder) {
  this.baseCAFolder = caFolder;
  this.certsFolder = this.baseCAFolder + '/certs';
  this.keysFolder = this.baseCAFolder + '/keys';
  try {
    FS.mkdirSync(this.baseCAFolder);
  } catch (e) { /* no op */ }
  try {
    FS.mkdirSync(this.certsFolder);
  } catch (e) { /* no op */ }
  try {
    FS.mkdirSync(this.keysFolder);
  } catch (e) { /* no op */ }
  try {
    var stats = FS.statSync(this.certsFolder + '/ca.pem');
    this.loadCA();
  } catch (e) {
    console.error('Failed to load CA', e);
    process.exit(1);
  }
  this.currentlyGenerating = {};
};

CA.prototype.randomSerialNumber = function () {
	// generate random 16 bytes hex string
	var sn = '';
	for (var i=0; i<4; i++) {
		sn += ('00000000' + Math.floor(Math.random()*Math.pow(256, 4)).toString(16)).slice(-8);
	}
	return sn;
}

CA.prototype.loadCA = function () {
  var certPEM = FS.readFileSync(this.certsFolder + '/ca.pem');
  var keyPrivatePEM = FS.readFileSync(this.keysFolder + '/ca.private.key');
  var keyPublicPEM = FS.readFileSync(this.keysFolder + '/ca.public.key');
  var password = FS.readFileSync(this.keysFolder + '/ca.private.password').toString().replace(/\n/, '');

  this.CAcert = pki.certificateFromPem(certPEM);

  var privateKey = pki.decryptRsaPrivateKey(keyPrivatePEM, password);
  var publicKey = pki.publicKeyFromPem(keyPublicPEM);

  this.CAkeys = {
      'privateKey': privateKey,
      'publicKey': publicKey
  };
};

CA.prototype.generateServerCertificateKeys = function (hostname, cb) {
  var keysServer = pki.rsa.generateKeyPair(1024);
  var certServer = pki.createCertificate();
  certServer.publicKey = keysServer.publicKey;
  certServer.serialNumber = this.randomSerialNumber();
  certServer.validity.notBefore = new Date();
  certServer.validity.notAfter = new Date();
  certServer.validity.notAfter.setFullYear(certServer.validity.notBefore.getFullYear() + 2);
  var attrsServer = ServerAttrs.slice(0);
  attrsServer.unshift({
    name: 'commonName',
    value: hostname
  })
  certServer.setSubject(attrsServer);
  certServer.setIssuer(this.CAcert.issuer.attributes);
  certServer.setExtensions(ServerExtensions);
  certServer.sign(this.CAkeys.privateKey, Forge.md.sha256.create());
  var certPem = pki.certificateToPem(certServer);
  var keyPrivatePem = pki.privateKeyToPem(keysServer.privateKey)
  var keyPublicPem = pki.publicKeyToPem(keysServer.publicKey)
  FS.writeFile(this.certsFolder + '/' + hostname + '.pem', certPem);
  FS.writeFile(this.keysFolder + '/' + hostname + '.key', keyPrivatePem);
  FS.writeFile(this.keysFolder + '/' + hostname + '.public.key', keyPublicPem);
  cb(certPem, keyPrivatePem);
};

CA.prototype.getServerCertificateKeys = function (hostname, cb) {
  if (this.currentlyGenerating.hasOwnProperty(hostname)) {
    this.currentlyGenerating[hostname].push(cb);
  } else {
    this.currentlyGenerating[hostname] = [cb];
    FS.stat(this.certsFolder + '/' + hostname + '.pem', function (err, stat) {
      if (typeof err !== 'undefined') {
        this.generateServerCertificateKeys(hostname, function (cert, key) {
          // possible race condition here...
          var tmp = this.currentlyGenerating[hostname];
          tmp.forEach(function (c) {
            c(cert, key);
          });
          delete this.currentlyGenerating[hostname];
        }.bind(this));
      } else {
        FS.readFile(this.certsFolder + '/' + hostname + '.pem', function (err, dataCert) {
          FS.readFile(this.keysFolder + '/' + hostname + '.key', function (err, dataKey) {
            // possible race condition here...
            var tmp = this.currentlyGenerating[hostname];
            tmp.forEach(function (c) {
              c(dataCert, dataKey);
            });
            delete this.currentlyGenerating[hostname];
          }.bind(this));
        }.bind(this));
      }
    }.bind(this));
  }
};

CA.prototype.getCACertPath = function () {
  return this.certsFolder + '/ca.pem';
};
module.exports = CA;
