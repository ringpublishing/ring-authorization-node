var DLSigner = require('../ring-authorization-node').DLSigner;

var opt = {
    service: 'pulsapi',
    scope: 'dl1_request',
    solution: 'region',
    accessKeyId: 'AKID',
    secret: 'TEST'
};

var request = {
    "method": "GET",
    "uri": '/test?abc=aaa',
    "headers": {
        host: 'test',
        "Content-Type": 'application/json',
        "Accept": 'application/json',
        'X-DL-Date': '20190129T120200Z'
    }
};

var buffer = Buffer.from('test', 'utf-8');

var request2 = {
    "method": "POST",
    "uri": '/test',
    "headers": {
        host: 'test',
        "Content-Type": 'application/json',
        "Accept": 'application/json',
    },
    "body": buffer
};

var signer = new DLSigner(opt);

// var sign = signer.sign(request);
var sign = signer.sign(request2);

console.log(sign);
