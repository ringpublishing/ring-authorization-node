var DLSigner = require('../ring-authorization-node').DLSigner;

var opt = {
    service: 'pulsapi',
    scope: 'dl1_request',
    solution: 'region',
    accessKeyId: 'AKID',
    secret: 'TEST'
};
var buffer = new Buffer([12,14,16]);

var request = {
    "method": "GET",
    "uri": '/test?abc=aaa',
    "headers": {
        host: 'test',
        "Content-Type": 'application/json',
        "Accept": 'application/json',
        'X-DL-Date': '20190129T101500Z'
    }
};

var signer = new DLSigner(opt);

var sign = signer.sign(request);

console.log(sign);
