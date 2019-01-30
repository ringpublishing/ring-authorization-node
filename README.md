# ring-authorization-node

Library for DreamLab Authenticating Requests for Node.js (version > 0.8.28).

# Example usage

Firstly, DLSigner object should be created with required accessKey, secretKey 
and service parameters.

```js
var DLSigner = require('../ring-authorization-node').DLSigner;

var options = {
    service: 'pulsapi',
    accessKey: 'ACCESSKEY',
    secretKey: 'SECRETKEY'
};

var signer = new DLSigner(options);
```

Afterwards, DLSigner can sign request:

```js
var exampleRequest = {
    'method': 'GET',
    'uri': '/test?param1=val1',
    'headers': {
        'Host': 'test',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
};

var sign = signer.sign(exampleRequest);
console.log(sign);
// { 
//      Authorization: 'DL-HMAC-SHA256 Credential=ACCESSKEY/20190130/RING/pulsapi/dl1_request,SignedHeaders=accept;content-type;host;x-dl-date,Signature=134d6e5fdfb4f16263ac622a94fb5eee612d234be2ba86b093215ebdc80af1f9',
//      'X-DL-Date': '20190130T145324Z'
// }
```
A request **must** contain *method* and *headers* with *Host*, *Content-Type*.

## Request payload

If a request contains a body, then it should be passed as a **Buffer**, ex:
```js
var postRequest = {
    'method': 'POST',
    'uri': '/resources',
    'headers': {
        'Host': 'test',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    },
    'body': new Buffer('request body')
};
```
