# ring-authorization-node

RING requests authorization library for Node.js (version > 6.0.0).
For more information, please read [RING authorization docs](http://doc.dreamlab/RingAuth/index.html)

# Example usage

When sending HTTP requests to RING, all requests must be signed so that RING can identify who sent them.
In order to sign a request, you need to provide RING access key, RING secret key and the name of the service you make a
request to. If you do not know what those properties are or how to get them, please contact someone from RING Publishing.

```js
let DLSigner = require('../ring-authorization-node').DLSigner;

let options = {
    'service': 'pulsapi',
    'accessKey': 'accessKey',
    'secretKey': 'secretKey'
};

let signer = new DLSigner(options);
```

Then, prepare a request which **must** contain *method* and *headers* fields. Moreover, *headers* **must** contain *Host*
and *Content-Type* fields.

```js
let request = {
    'method': 'GET',
    'uri': '/resources?param1=val1',
    'headers': {
        'Host': 'api.ring.example.eu',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
};

let signature = signer.sign(request);
console.log(signature);
// { 
//      Authorization: 'DL-HMAC-SHA256 Credential=accessKey/20190618/RING/pulsapi/dl1_request,SignedHeaders=accept;content-type;host;x-dl-date,Signature=1415a283aa8652369ba045711dd92ae9f5968de76a9d2ee2c6b2feb7c0f24599',
//      'X-DL-Date': '20190618T101228Z'
// }
```

Finally, add calculated signature to the request.

```js
let signedRequest = {
    'method': 'GET',
    'uri': '/resources?param1=val1',
    'headers': {
        'Host': 'api.ring.example.eu',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'DL-HMAC-SHA256 Credential=accessKey/20190618/RING/pulsapi/dl1_request,SignedHeaders=accept;content-type;host;x-dl-date,Signature=1415a283aa8652369ba045711dd92ae9f5968de76a9d2ee2c6b2feb7c0f24599',
        'X-DL-Date': '20190618T101228Z'
    }
};
```

## POST request

If a request contains a body, then it should be passed as a **Buffer**.

```js
let request = {
    'method': 'POST',
    'uri': '/resources',
    'headers': {
        'Host': 'api.ring.example.eu',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    },
    'body': new Buffer('request body')
};
```
