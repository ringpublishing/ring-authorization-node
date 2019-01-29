var crypto = require('crypto');
var moment = require('moment');

var REQUEST_EXPIRATION_TIME = 15; // in minutes

var acceptedHashMethods = ['sha224', 'sha256', 'sha384', 'sha512'];
var acceptedMethod = 'DL-HMAC-SHA';
var acceptedService = 'pulsapi';
var acceptedRequestScope = 'dl1_request';


var DLSigner = function (options) {
    this.algorithm = options.algorithm ? options.algorithm : 'DL-HMAC-SHA256';
    this.options = options;
    this.options['scope'] = this.options['scope'] ? this.options['scope'] : 'dl1_request';
    this.options['solution'] = this.options['solution'] ? this.options['solution'] : 'RING';
    this.hashAlg = this.algorithm.split('-').slice(-1)[0].toLowerCase();

    this._validate();
};

DLSigner.prototype._validate = function () {
    if (typeof (this.algorithm) !== 'string' || !this.algorithm.indexOf(acceptedMethod) === 0) {
        throw Error('Invalid algorithm!');
    }
    if (acceptedHashMethods.indexOf(this.hashAlg) < 0) {
        throw Error('Invalid hash method');
    }
    if (!this.options['secretKey']) {
        throw Error('Secret key is missing!');
    }
    if (!this.options['accessKey']) {
        throw Error('Access key ID is missing!');
    }
    if (!this.options['solution']) {
        throw Error('Solution in options missing!');
    }
    if (this.options['service'] !== acceptedService) {
        throw Error('Invalid service option!')
    }
    if (this.options['scope'] !== acceptedRequestScope) {
        throw Error('Invalid scope option!');
    }
};

DLSigner.prototype._sign = function (key, msg, hexOutput) {
    hexOutput = hexOutput ? hexOutput : false;
    if (!msg) {
        msg = '';
    }
    var sign = crypto.createHmac(this.hashAlg, key);
    sign.update(msg, 'utf-8');
    return hexOutput ? sign.digest('hex') : sign.digest();
};

DLSigner.prototype._hash = function (msg, hexOutput, isPayload) {
    hexOutput = hexOutput ? hexOutput : false;
    isPayload = isPayload ? isPayload : false;

    if (!msg) {
        msg = '';
    }
    var sign = crypto.createHash(this.hashAlg);
    isPayload ? sign.update(msg) : sign.update(msg, 'utf-8');
    return hexOutput ? sign.digest('hex') : sign.digest();
};

DLSigner.prototype._prepareStringToSign = function (timeStamp, credentialsString, req_hash) {
    return this.algorithm + '\n' + moment(timeStamp, 'YYYYMMDD[T]HHmmss[Z]').format('YYYYMMDD[T]HHmmss[Z]') + '\n' + credentialsString + '\n' + req_hash;
};

DLSigner.prototype._prepareCanonicalHeaders = function (headers) {
    var res = '';
    var can_header;
    var sortedHeaders = Object.keys(headers).sort();

    for (var i = 0; i < sortedHeaders.length; i++) {
        can_header = sortedHeaders[i];
        res += can_header + ':' + headers[sortedHeaders[i]].trim();
        if (i !== sortedHeaders.length - 1) {
            res += '\n';
        }
    }
    return res;
};

DLSigner.prototype._prepareSignedHeaders = function (headers) {
    var signedHeaders = [];
    var signedHeader;
    var sortedHeaders = Object.keys(headers).sort();
    for (var i = 0; i < sortedHeaders.length; i++) {
        signedHeader = sortedHeaders[i].trim();
        signedHeaders.push(signedHeader);
    }
    return signedHeaders.join(';');
};

DLSigner.prototype._prepareCanonicalQueryString = function (request) {
    var uri = (request.uri) ? request.uri : '/';
    var params = '';
    var canonicalQueryString = '';

    if (uri.indexOf('?') >= 0) {
        uri = uri.split('?');
        params = uri[1];
        params = params.split('&').sort();
        var param;
        var val;
        for (var i = 0; i < params.length; i++) {
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
    var requestDateLimit = moment().clone(dlDate).subtract(REQUEST_EXPIRATION_TIME, 'minutes');
    return moment(dlDate, 'YYYYMMDD[T]HHmmss[Z]').isAfter(requestDateLimit);
};

DLSigner.prototype._getSigningKey = function (dateStamp, solution, service, request_scope) {
    var sign = this._sign('DL' + this.options['secretKey'], dateStamp);
    sign = this._sign(sign, solution);
    sign = this._sign(sign, service);
    return this._sign(sign, request_scope);
};

DLSigner.prototype._getCredentialString = function (dateStamp, solution, service, scope) {
    var credentials = [dateStamp, solution, service, scope];
    return credentials.join('/');
};

DLSigner.prototype._validateRequest = function (request, headers) {
    if (!request['method']) {
        throw Error('Method in options is missing!');
    }
    if (!request['headers']) {
        throw Error('No headers provided!');
    }
    if (!headers['host']) {
        throw Error('Host is missing!');
    }
    if (!headers['content-type']) {
        throw Error('Content-Type is missing!');
    }
    if (request['body'] && !Buffer.isBuffer(request['body'])) {
        throw Error('Invalid payload!');
    }
    if (!this.isNotOutdated(headers['x-dl-date'])) {
        throw Error('Invalid X-DL-Date header!');
    }
};

DLSigner.prototype._copyHeaders = function (headers) {
    var copiedHeaders = {};
    for (var i in headers) {
        copiedHeaders[i.toLowerCase()] = headers[i];
    }
    return copiedHeaders;
};

/**
 * Signs request and adds X-DL-Date header
 * @param {object} request - request to be signed
 * @returns {object} - signed request
 */
DLSigner.prototype.sign = function (request) {
    var copiedHeaders = this._copyHeaders(request.headers);
    if (!copiedHeaders['x-dl-date']) {
        copiedHeaders['x-dl-date'] = moment().format('YYYYMMDD[T]HHmmss[Z]');
    }
    this._validateRequest(request, copiedHeaders);
    var signedHeaders = this._prepareSignedHeaders(copiedHeaders);

    var canonicalRequest = this._prepareCanonicalRequest(
        request['method'], this._prepareCanonicalURI(request['uri']), this._prepareCanonicalQueryString(request),
        this._prepareCanonicalHeaders(copiedHeaders),
        signedHeaders, this._hash(request.body, true, true));

    var canonicalRequestHash = this._hash(canonicalRequest, true);
    var dateStamp = moment(copiedHeaders['x-dl-date'], 'YYYYMMDD[T]HHmmss[Z]').format('YYYYMMDD');

    var credentialsString = this._getCredentialString(dateStamp, this.options['solution'],
        this.options['service'], this.options['scope']);

    var stringToSign = this._prepareStringToSign(copiedHeaders['x-dl-date'], credentialsString, canonicalRequestHash);
    var signingKey = this._getSigningKey(dateStamp, this.options['solution'],
        this.options['service'], this.options['scope']);

    var authorizationSignature = this._sign(signingKey, stringToSign, true);

    return {
        'Authorization': this.algorithm + ' ' + 'Credential=' + this.options['accessKey'] + '/' +
            credentialsString + ',SignedHeaders=' + signedHeaders + ',Signature=' + authorizationSignature,
        'X-DL-Date': copiedHeaders['x-dl-date']
    };
};

exports.DLSigner = DLSigner;
