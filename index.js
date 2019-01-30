var crypto = require('crypto');
var moment = require('moment');


var REQUEST_EXPIRATION_TIME = 15; // in minutes

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
    this.algorithm = options.algorithm ? options.algorithm : 'DL-HMAC-SHA256';
    this.options = options;
    this.options.scope = this.options.scope ? this.options.scope : 'dl1_request';
    this.options.solution = this.options.solution ? this.options.solution : 'RING';
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
    if (acceptedHashMethods.indexOf(this.hashAlg) < 0) {
        throw Error('Invalid hash method');
    }
    if (!this.options.secretKey) {
        throw Error('Secret key is missing!');
    }
    if (!this.options.accessKey) {
        throw Error('Access key ID is missing!');
    }
    if (this.options.service !== acceptedService) {
        throw Error('Invalid service option!')
    }
    if (this.options.scope !== acceptedRequestScope) {
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
 * @param {string} headers - input headers
 * @returns {string} Canonical headers
 */
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

/**
 * Sorts and returns signed headers string
 * @param {string} headers - input headers
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

/**
 * Prepares and returns a canonical uri
 * @param {string} uri - input uri
 * @returns {string} canonical uri from input
 */
DLSigner.prototype._prepareCanonicalURI = function (uri) {
    return uri.split('?')[0];
};

/**
 * Prepares and returns a canonical request
 * @param {object} request - request
 * @param {string} headers - sorted headers with x-dl-date header
 * @param {string} signedHeaders - signed headers string
 * @returns {string} string of canonical request
 */
DLSigner.prototype._prepareCanonicalRequest = function (request, headers, signedHeaders) {
    return encodeURIComponent(request.method) + '\n' + encodeURIComponent(this._prepareCanonicalURI(request.uri)) +
        '\n' + this._prepareCanonicalQueryString(request) + '\n' + this._prepareCanonicalHeaders(headers) + '\n'
        + signedHeaders + '\n' + this._hash(request.body, true, true);
};

/**
 * Checks if input date is outdated
 * @param {string} dlDate - date to be checked
 * @returns boolean that determines if a dlDate is not valid
 */
DLSigner.prototype.isOutdated = function (dlDate) {
    var requestDateLimit = moment().clone(dlDate).subtract(REQUEST_EXPIRATION_TIME, 'minutes');
    return moment(dlDate, 'YYYYMMDD[T]HHmmss[Z]').isBefore(requestDateLimit);
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
    if (!request.method) {
        throw Error('Method in options is missing!');
    }
    if (!request.headers) {
        throw Error('No headers provided!');
    }
    if (!headers.host) {
        throw Error('Host is missing!');
    }
    if (!headers['content-type']) {
        throw Error('Content-Type is missing!');
    }
    if (request.body && !Buffer.isBuffer(request.body)) {
        throw Error('Invalid payload!');
    }
    if (this.isOutdated(headers['x-dl-date'])) {
        throw Error('Invalid X-DL-Date header!');
    }
};

/**
 * Copies headers, changes letters to lowercase and adds x-dl-date header
 * @param {object} headers - headers to be copied
 * @returns {object} - copied, lowercase headers
 */
DLSigner.prototype._copyHeaders = function (headers) {
    var copiedHeaders = {};
    for (var i in headers) {
        copiedHeaders[i.toLowerCase()] = headers[i];
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
