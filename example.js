var DLSigner = require('../ring-authorization-node').DLSigner;

var options = {
    service: 'pulsapi',
    scope: 'dl1_request',
    solution: 'region',
    accessKey: 'AKID',
    secretKey: 'SECRETKEY'
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
    'uri': '/test',
    'headers': {
        'Host': 'test',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    },
    'body': buffer
};

var signer = new DLSigner(options);

var sign = signer.sign(request);
var sign2 = signer.sign(request2);

console.log(sign);
console.log(sign2);
