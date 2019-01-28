const crypto = require('crypto');
const moment = require('moment');


const acceptedHashMethods = ['sha224', 'sha256', 'sha384', 'sha512'];
const acceptedMethod = 'DL-HMAC-SHA';
const acceptedService = 'pulsapi';
const acceptedRequestScope = 'dl1-request';


let DLSigner = function (options, algorithm = 'DL-HMAC-SHA256') {
    this.algorithm = algorithm;
    this.options = options;

    this._validate();
    this.hashAlg = this.algorithm.split('-').slice(-1)[0].toLowerCase();
};

DLSigner.prototype._validate = function () {
    if (typeof (this.algorithm) !== 'string' || !this.algorithm.startsWith(acceptedMethod)) {
        throw Error('Invalid algorithm!');
    }
    if (!acceptedHashMethods.includes(this.algorithm.split('-').slice(-1)[0].toLowerCase())) {
        throw Error('Invalid hash method');
    }
    if (!this.options['secret']) {
        throw Error("Secret access key is missing!");
    }
    if (!this.options['accessKeyId']) {
        throw Error("Access key ID is missing!");
    }
    if (!this.options['solution']) {
        throw Error("Solution in options missing!");
    }
    if (this.options['service'] !== acceptedService) {
        throw Error("Invalid 'service' option!");
    }
    if (this.options['scope'] !== acceptedRequestScope) {
        throw Error("Invalid 'scope' option!");
    }
};

DLSigner.prototype._sign = function (key, msg, hex_output = false) {
    if (!msg) msg = "";
    let sign = crypto.createHmac(this.hashAlg, key);
    sign.update(msg, "utf-8");
    return hex_output ? sign.digest('hex') : sign.digest();
};

DLSigner.prototype._hash = function (msg, hex_output = false, is_payload = false) {
    if (!msg) msg = "";
    let sign = crypto.createHash(this.hashAlg);
    is_payload ? sign.update(msg) : sign.update(msg, 'utf-8');
    return hex_output ? sign.digest('hex') : sign.digest();
};

DLSigner.prototype._prepareStringToSign = function (timeStamp, credentialsString, req_hash) {
    return this.algorithm + '\n' + moment(timeStamp).format('YYYYMMDD[T]HHmmss[Z]') + '\n' + credentialsString + '\n' + req_hash;
};

DLSigner.prototype._prepareCanonicalHeaders = function (headers) {
    let res = '';
    let can_header;
    let sortedHeaders = Object.keys(headers).sort(function (a, b) {
        return a.toLowerCase().localeCompare(b.toLowerCase())
    });
    for (let i = 0; i < sortedHeaders.length; i++) {
        can_header = sortedHeaders[i].replace('/ /g', "").toLowerCase();
        res += can_header + ':' + headers[sortedHeaders[i]].trim();
        if (i !== sortedHeaders.length - 1) res += '\n';
    }
    return res;
};

DLSigner.prototype._prepareSignedHeaders = function (headers) {
    let signedHeaders = [];
    let signedHeader;
    for (let header of Object.keys(headers).sort(function (a, b) {
        return a.toLowerCase().localeCompare(b.toLowerCase())
    })) {
        signedHeader = header.replace('/ /g', '').trim().toLowerCase();
        signedHeaders.push(signedHeader);
    }
    return signedHeaders.join(';');
};

DLSigner.prototype._prepareCanonicalQueryString = function (request) {
    let uri = (request.uri) ? request.uri : '/';
    let params = '';
    let canonicalQueryString = '';

    if (uri.includes('?')) {
        uri = uri.split('?');
        params = uri[1];
        params = params.split('&');
        let param;
        let val;
        for (let i = 0; i < params.length; i++) {
            param = params[i].split('=');
            val = (param[1]) ? param[1] : '';
            canonicalQueryString += encodeURIComponent(param[0]) + '=' + encodeURIComponent(val);
            if (i !== params.length - 1) {
                canonicalQueryString += '&';
            }
        }
    }
    return canonicalQueryString;
};

DLSigner.prototype._prepareCanonicalURI = function (uri) {
    return uri.split('?')[0];
};

DLSigner.prototype._prepareCanonicalRequest = function (method, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash) {
    return encodeURIComponent(method) + '\n' + encodeURIComponent(canonicalUri) +
        '\n' + canonicalQueryString + '\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + payloadHash;
};

DLSigner.prototype.isNotOutdated = function (dlDate) {
    let requestDateLimit = moment().subtract(15, 'minutes');
    return moment(dlDate).isAfter(requestDateLimit);
};


DLSigner.prototype._getSigningKey = function (dateStamp, solution, service, request_scope) {
    let sign = this._sign('DL' + this.options['secret'], dateStamp);
    sign = this._sign(sign, solution);
    sign = this._sign(sign, service);
    return this._sign(sign, request_scope);
};

DLSigner.prototype._getCredentialString = function (dateStamp, solution, service, scope) {
    let credentials = [dateStamp, solution, service, scope];
    return credentials.join('/');
};

DLSigner.prototype._preSign = function (request, headers) {
    if (!request['method']) {
        throw Error("Method in options is missing!");
    }
    if (!request['headers']) {
        throw Error("No headers provided!");
    }
    if (!headers['host']) {
        throw Error("Host is missing!");
    }
    if (!headers['Content-Type']) {
        throw Error("Content-Type is missing!");
    }
    if (request['body'] && !Buffer.isBuffer(request['body'])) {
        throw Error("Invalid payload!");
    }
    if (!this.isNotOutdated(headers['X-DL-Date'])) {
        throw Error("Invalid 'X-DL-Date' header!");
    }
};

/**
 * Signs request and adds X-DL-Date header
 * @param {object} request - request to be signed
 * @returns {object} - signed request
 */
DLSigner.prototype.sign = function (request) {
    let copiedHeaders = Object.assign({}, request.headers);
    if (!request.headers['X-DL-Date']) {
        copiedHeaders['X-DL-Date'] = moment(copiedHeaders['X-DL-Date']).utc().format('YYYYMMDD[T]HHmmss[Z]');
    }
    this._preSign(request, copiedHeaders);
    let signedHeaders = this._prepareSignedHeaders(copiedHeaders);

    let canonicalRequest = this._prepareCanonicalRequest(
        request['method'], this._prepareCanonicalURI(request['uri']), this._prepareCanonicalQueryString(request),
        this._prepareCanonicalHeaders(copiedHeaders),
        signedHeaders, this._hash(request.body, true, true));

    let canonicalRequestHash = this._hash(canonicalRequest, true);
    let dateStamp = moment(copiedHeaders['X-DL-Date']).format('YYYYMMDD');

    let credentialsString = this._getCredentialString(dateStamp, this.options['solution'],
        this.options['service'], this.options['scope']);

    let stringToSign = this._prepareStringToSign(copiedHeaders['X-DL-Date'], credentialsString, canonicalRequestHash);

    let signingKey = this._getSigningKey(dateStamp, this.options['solution'],
        this.options['service'], this.options['scope']);
    let authorizationSignature = this._sign(signingKey.toString(), stringToSign, true);

    return {
        "Authorization": this.algorithm + ' ' + 'Credential=' + this.options['accessKeyId'] + '/' +
            credentialsString + ',SignedHeaders=' + signedHeaders + ',Signature=' + authorizationSignature,
        "X-DL-Date": copiedHeaders['X-DL-Date']
    };
};

module.exports = {
    DLSigner
};
