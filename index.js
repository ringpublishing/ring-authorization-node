var crypto = require('crypto');
var moment = require('moment');


var DEFAULT_SOLUTION = 'RING';
var DEFAULT_REQUEST_SCOPE = 'dl1_request';
var DEFAULT_ALGORITHM = 'DL-HMAC-SHA256';

var acceptedHashMethods = ['sha224', 'sha256', 'sha384', 'sha512'];
var acceptedMethod = 'DL-HMAC-SHA';
var acceptedService = 'pulsapi';
var acceptedRequestScope = 'dl1_request';

/**
 * Request signer for DL authentication. Calculates request signature using HMAC algorithm, basing on request headers, uri and others.
 * Available hash algorithms - sha224, sha256, sha384, sha512. Accepted services - 'pulsapi'.
 * @class DLSigner
 * @param options {object} - object that must contain secretKey, accessKey, service params.
 */
var DLSigner = function (options) {
    this.algorithm = options.algorithm ? options.algorithm : DEFAULT_ALGORITHM;
    this.options = options;
    this.options.scope = this.options.scope ? this.options.scope : DEFAULT_REQUEST_SCOPE;
    this.options.solution = this.options.solution ? this.options.solution : DEFAULT_SOLUTION;
    this.hashAlg = this.algorithm.split('-').slice(-1)[0].toLowerCase();

    this._validateOptions();
};

/**
 * Validates options parameter
 */
DLSigner.prototype._validateOptions = function () {
    if (typeof (this.algorithm) !== 'string' || !this.algorithm.indexOf(acceptedMethod) === 0) {
        throw Error('Invalid algorithm!');
    }
    if (typeof (this.hashAlg) !== 'string' || acceptedHashMethods.indexOf(this.hashAlg) < 0) {
        throw Error('Invalid hash method');
    }
    if (typeof (this.options.secretKey) !== 'string') {
        throw Error('Invalid secret key!');
    }
    if (typeof (this.options.accessKey) !== 'string') {
        throw Error('Invalid access key!');
    }
    if (typeof (this.options.service) !== 'string' || this.options.service !== acceptedService) {
        throw Error('Invalid service option!')
    }
    if (typeof (this.options.scope) !== 'string' || this.options.scope !== acceptedRequestScope) {
        throw Error('Invalid scope option!');
    }
};

/**
 * Performs HMAC digest
 * @param {string} key - key
 * @param {string} msg - message to be digested
 * @param {boolean} hexOutput - determines if a message should be returned in hex encoding
 * @returns {string} Digested message
 */
DLSigner.prototype._sign = function (key, msg, hexOutput) {
    hexOutput = hexOutput ? hexOutput : false;
    msg = msg ? msg : '';

    var sign = crypto.createHmac(this.hashAlg, key);
    sign.update(msg, 'utf-8');
    return hexOutput ? sign.digest('hex') : sign.digest();
};

/**
 * Performs hash digest
 * @param {string} msg - message to be digested
 * @param {boolean} hexOutput - determines if a message should be returned in hex encoding
 * @param {boolean} isPayload - determines if a message is request payload
 * @returns {string} Message hash
 */
DLSigner.prototype._hash = function (msg, hexOutput, isPayload) {
    hexOutput = hexOutput ? hexOutput : false;
    isPayload = isPayload ? isPayload : false;
    msg = msg ? msg : '';

    var sign = crypto.createHash(this.hashAlg);
    isPayload ? sign.update(msg) : sign.update(msg, 'utf-8');
    return hexOutput ? sign.digest('hex') : sign.digest();
};

/**
 * Creates string to sign
 * @param {string} timeStamp - timestamp in format YYYYMMDDTHHmmssZ
 * @param {string} credentialsString -
 * @param {string} canonicalRequest - string containing canonical request
 * @returns {string} string to sign
 */
DLSigner.prototype._prepareStringToSign = function (timeStamp, credentialsString, canonicalRequest) {
    return this.algorithm + '\n' + timeStamp + '\n' + credentialsString + '\n' + this._hash(canonicalRequest, true);
};

/**
 * Sorts and returns canonical headers string
 * @param {object} headers - input headers
 * @returns {string} Canonical headers
 */
DLSigner.prototype._prepareCanonicalHeaders = function (headers) {
    var res = '';
    var sortedHeaders = Object.keys(headers).sort();
    var canHeader;
    for (var i = 0; i < sortedHeaders.length; i++) {
        canHeader = sortedHeaders[i];
        res += canHeader + ':' + headers[sortedHeaders[i]].trim();
        if (i !== sortedHeaders.length - 1) {
            res += '\n';
        }
    }
    return res;
};

/**
 * Sorts and returns signed headers string
 * @param {object} headers - input headers
 * @returns {string} string of signed headers
 */
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

/**
 * Parses query string
 * @param {object} request - input request
 * @returns {string} string of canonical query string
 */
DLSigner.prototype._prepareCanonicalQueryString = function (request) {
    var uri = request.uri ? request.uri : '/';
    var params = '';
    var canonicalQueryString = '';

    if (uri.indexOf('?') >= 0) {
        uri = uri.split('?');
        params = uri[1].split('&').sort();
        for (var i = 0; i < params.length; i++) {
            var param = params[i].split('=');
            var val = (param[1]) ? param[1] : '';
            canonicalQueryString += this._uriEncode(param[0], true) + '=' + this._uriEncode(val, true);
            if (i !== params.length - 1) {
                canonicalQueryString += '&';
            }
        }
    }
    return canonicalQueryString;
};

/**
 * Prepares and returns a canonical uri
 * @param {string} uri - input uri
 * @returns {string} canonical uri from input
 */
DLSigner.prototype._prepareCanonicalURI = function (uri) {
    return uri ? this._uriEncode(uri.split('?')[0], false) : '/';
};

/**
 * Prepares and returns a canonical request
 * @param {object} request - request
 * @param {object} headers - sorted headers with x-dl-date header
 * @param {string} signedHeaders - signed headers string
 * @returns {string} string of canonical request
 */
DLSigner.prototype._prepareCanonicalRequest = function (request, headers, signedHeaders) {
    return request.method + '\n' + this._prepareCanonicalURI(request.uri) +
        '\n' + this._prepareCanonicalQueryString(request) + '\n' + this._prepareCanonicalHeaders(headers) + '\n'
        + signedHeaders + '\n' + this._hash(request.body, true, true);
};

/**
 * Checks if input date is valid
 * @param {string} dlDate - date to be checked
 * @returns boolean that determines if a dlDate is not valid
 */
DLSigner.prototype._isIncorrectDate = function (dlDate) {
    return !moment(dlDate, 'YYYYMMDD[T]HHmmss[Z]', true).isValid();
};

/**
 * Generates signing key
 * @param {string} dateStamp - date in format YYYYMMDD
 * @returns signing key
 */
DLSigner.prototype._getSigningKey = function (dateStamp) {
    var sign = this._sign('DL' + this.options.secretKey, dateStamp);
    sign = this._sign(sign, this.options.solution);
    sign = this._sign(sign, this.options.service);
    return this._sign(sign, this.options.scope);
};

/**
 * Generates credential string
 * @param {string} dateStamp - date in format YYYYMMDD
 * @returns {string}
 */
DLSigner.prototype._getCredentialString = function (dateStamp) {
    var credentials = [dateStamp, this.options.solution, this.options.service, this.options.scope];
    return credentials.join('/');
};

/**
 * Validates request and headers against required fields
 * @param {object} request - request to be validate
 * @param {object} headers - headers to be validate
 */
DLSigner.prototype._validateRequest = function (request, headers) {
    if (typeof (request.method) !== 'string') {
        throw Error('Invalid request method!');
    }
    if (typeof (request.headers) !== 'object') {
        throw Error('Invalid request headers!');
    }
    if (typeof (headers.host) !== 'string') {
        throw Error('Invalid Host header!');
    }
    if (typeof (headers['content-type']) !== 'string') {
        throw Error('Invalid Content-Type header!');
    }
    if (request.body && !Buffer.isBuffer(request.body)) {
        throw Error('Invalid payload!');
    }
    if (this._isIncorrectDate(headers['x-dl-date'])) {
        throw Error('Invalid X-DL-Date header!');
    }
};

/**
 * Encodes given input string
 * @param {string} input - input string
 * @param {boolean} encodeSlash - determines if slash should be encoded
 * @returns {string} - encoded result
 */
DLSigner.prototype._uriEncode = function (input, encodeSlash) {
    var unreservedCharacters = ['-', '_', '~', '.'];
    var res = '';

    for (var i = 0; i < input.length; i++) {
        var ch = input.charAt(i);
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
            unreservedCharacters.indexOf(ch) >= 0) {
            res += ch;
        } else if (ch === '/') {
            res += encodeSlash ? '%2F' : ch;
        } else {
            res += encodeURIComponent(ch);
        }
    }

    return res;
};

/**
 * Copies headers, changes letters to lowercase and adds x-dl-date header
 * @param {object} headers - headers to be copied
 * @returns {object} - copied, lowercase headers
 */
DLSigner.prototype._copyHeaders = function (headers) {
    var copiedHeaders = {};
    var headersFields = Object.keys(headers);
    for (var i = 0; i < headersFields.length; i++) {
        copiedHeaders[headersFields[i].toLowerCase()] = headers[headersFields[i]];
    }
    if (!copiedHeaders['x-dl-date']) {
        copiedHeaders['x-dl-date'] = moment().format('YYYYMMDD[T]HHmmss[Z]');
    }
    return copiedHeaders;
};

/**
 * Signs request by performing necessary steps
 * @param {object} request - request that will be signed. Must contain method param and headers with content-type, host.
 * May contain body param with request body, which must be a Buffer.
 * @returns {object} - Authorization header with signature and X-DL-Date header
 */
DLSigner.prototype.sign = function (request) {
    var copiedHeaders = this._copyHeaders(request.headers);

    this._validateRequest(request, copiedHeaders);
    var signedHeaders = this._prepareSignedHeaders(copiedHeaders);

    var canonicalRequest = this._prepareCanonicalRequest(request, copiedHeaders, signedHeaders);

    var dateStamp = moment(copiedHeaders['x-dl-date'], 'YYYYMMDD[T]HHmmss[Z]').format('YYYYMMDD');

    var credentialsString = this._getCredentialString(dateStamp);

    var authorizationSignature = this._sign(this._getSigningKey(dateStamp),
        this._prepareStringToSign(copiedHeaders['x-dl-date'], credentialsString, canonicalRequest),
        true);

    return {
        'Authorization': this.algorithm + ' ' + 'Credential=' + this.options.accessKey + '/' +
            credentialsString + ',SignedHeaders=' + signedHeaders + ',Signature=' + authorizationSignature,
        'X-DL-Date': copiedHeaders['x-dl-date']
    };
};

exports.DLSigner = DLSigner;
