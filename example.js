let DLSigner = require('../ring-authorization-node').DLSigner;

const opt = {
    service: 'pulsapi',
    scope: 'dl1-request',
    solution: 'region',
    accessKeyId: 'AKID',
    secret: 'TEST'
};
var buffer = new Buffer([12,14,16]);

const request = {
    "method": "GET",
    "uri": '/test?abc=aaa',
    "headers": {
        host: 'test',
        "Content-Type": 'application/json',
        "Accept": 'application/json',
        'X-DL-Date': '20190128T155100Z'
    }
};

let signer = new DLSigner(opt);

var sign = signer.sign(request);

console.log(sign);
