var DLSigner = require('../ring-authorization-node').DLSigner;

var options = {
    service: 'pulsapi',
    scope: 'dl1_request',
    accessKey: 'accessKey',
    secretKey: 'secretKey'
};

var request = {
    'method': 'GET',
    'uri': '/test?abc=aaa',
    'headers': {
        'Host': 'test',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
};

var buffer = new Buffer('test');

var request2 = {
    'method': 'POST',
    'uri': '/resources',
    'headers': {
        'Host': 'api.ring.example.eu',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    },
    'body': buffer
};

var signer = new DLSigner(options);

var signature = signer.sign(request);
var signature2 = signer.sign(request2);

console.log(signature);
console.log(signature2);
