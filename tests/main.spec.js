var expect = require('chai').expect;
var DLSigner = require('../index').DLSigner;
var moment = require('moment');

describe('RingAuthorization', function () {
    describe('GET request', function () {
        var request = {
            "method": "GET",
            "uri": '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20',
            "headers": {
                "host": 'test',
                "Content-Type": 'application/json',
                "Accept": 'application/json'
            }
        };
        var opt = {
            service: 'pulsapi',
            scope: 'dl1-request',
            solution: 'region',
            accessKeyId: 'AKID',
            secret: 'TEST'
        };
        describe('Invalid algorithm', function () {
            it('Should throw Error', function () {
                expect(function () {
                    new DLSigner(opt, "TEST")
                }).to.throw();
            });
        });
        describe('Invalid options', function () {
            var invalidOpt = {};
            it('Should throw Error', function () {
                expect(function () {
                    new DLSigner(invalidOpt)
                }).to.throw();
            });
        });
        describe('Hashing', function () {
            it('Should return correct SHA256 of a string', function () {
                const testHash = '9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08'.toLowerCase(); // 'test' sha256 hash
                const signer = new DLSigner(opt);
                expect(signer._hash('test', true)).to.equal(testHash);
            });
            it('Should return correct SHA512 of a string', function () {
                const testHash = 'EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD8E6F57F50028A8FF'.toLowerCase(); // 'test' sha256 hash
                const signer = new DLSigner(opt, 'DL-HMAC-SHA512');
                expect(signer._hash('test', true)).to.equal(testHash);
            });
        });
        describe('Correct payload hash', function () {
            it('Should return hash of empty string when payload is empty', function () {
                const testHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'.toLowerCase(); // empty string hash
                const signer = new DLSigner(opt);
                expect(signer._hash(request.body, true)).to.equal(testHash);
            });
        });
        describe('Correct Signed Headers', function () {
            it('Should return sorted and joined together signed headers', function () {
                const signer = new DLSigner(opt);
                expect(signer._prepareSignedHeaders(request.headers)).to.equal('accept;content-type;host');
            });
        });
        describe('Correct Canonical Headers', function () {
            it('Should correctly trim values and return lowercase names', function () {
                const signer = new DLSigner(opt);
                const headers = {
                    'HEADER1': '  val1  ',
                    'heaDer2': ' val2',
                    'Header3': 'va l3',
                    'header4': ''
                };
                const correctHeaders = 'header1:val1\nheader2:val2\nheader3:va l3\nheader4:';
                expect(signer._prepareCanonicalHeaders(headers)).to.equal(correctHeaders);
            });
        });
        describe('Sign', function () {
            it('Returns correct timestamp', function () {
                const signer = new DLSigner(opt);
                let timestamp = moment(signer.sign(request)['X-DL-Date']);
                expect(timestamp.isSame(new Date(), 'day')).to.equal(true);
            });
        });
        describe('Canonical Query String', function () {
            it('Returns correct canonical query string', function () {
                const signer = new DLSigner(opt);
                expect(signer._prepareCanonicalQueryString(request)).to.equal('marker=someMarker&max-keys=20&prefix=somePrefix');
            });
            it('Returns correct canonical query string with encoded values', function () {
                const signer = new DLSigner(opt);
                request.uri = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20&test=t^e s';
                expect(signer._prepareCanonicalQueryString(request)).to.equal('marker=someMarker&max-keys=20&prefix=somePrefix&test=t%5Ee%20s');
            });
            it('Returns correct canonical query string with encoded values and empty value', function () {
                const signer = new DLSigner(opt);
                request.uri = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20&test=t^e s&aws';
                expect(signer._prepareCanonicalQueryString(request)).to.equal('aws=&marker=someMarker&max-keys=20&prefix=somePrefix&test=t%5Ee%20s');
            });
            it('Returns correct canonical query string sorted by query param', function () {
                const signer = new DLSigner(opt);
                request.uri = '/examplebucket?zzz=someValue&Aaaa=someValue&aaa=20&test=t^e s&aws';
                expect(signer._prepareCanonicalQueryString(request)).to.equal('Aaaa=someValue&aaa=20&aws=&test=t%5Ee%20s&zzz=someValue');
            });
        });
        describe('Canonical Request', function () {
            it('Returns correct canonical request', function () {
                const signer = new DLSigner(opt);
                request.uri = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20';
                const headers = request['headers'];
                const canonicalRequest = signer._prepareCanonicalRequest(
                    request['method'], signer._prepareCanonicalURI(request['uri']), signer._prepareCanonicalQueryString(request),
                    signer._prepareCanonicalHeaders(headers),
                    signer._prepareSignedHeaders(headers), signer._hash(request.body, true, true));
                let correctValue = 'GET\n' +
                    encodeURIComponent('/examplebucket') + '\n' +
                    'marker=someMarker&max-keys=20&prefix=somePrefix\n' +
                    'accept:application/json\n' +
                    'content-type:application/json\n' +
                    'host:test\n' +
                    'accept;content-type;host\n' +
                    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
                expect(canonicalRequest).to.equal(correctValue);
            });
            it('Returns correct canonical request when no query string is provided', function () {
                const signer = new DLSigner(opt);
                request.uri = '/examplebucket';
                const headers = request['headers'];
                const canonicalRequest = signer._prepareCanonicalRequest(
                    request['method'], signer._prepareCanonicalURI(request['uri']), signer._prepareCanonicalQueryString(request),
                    signer._prepareCanonicalHeaders(headers),
                    signer._prepareSignedHeaders(headers), signer._hash(request.body, true, true));
                let correctValue = 'GET\n' +
                    encodeURIComponent('/examplebucket') + '\n' +
                    '\n' +
                    'accept:application/json\n' +
                    'content-type:application/json\n' +
                    'host:test\n' +
                    'accept;content-type;host\n' +
                    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
                expect(canonicalRequest).to.equal(correctValue);
            });
        });
    });

    describe('POST request', function () {
        var buffer = new Buffer('test');
        var invalidPayload = {
            "method": "POST",
            "uri": '/examplebucket',
            "headers": {
                "host": 'test',
                "Content-Type": 'application/json',
                "Accept": 'application/json'
            },
            "body": 'test'
        };
        var request = {
            "method": "POST",
            "uri": '/examplebucket',
            "headers": {
                "host": 'test',
                "Content-Type": 'application/json',
                "Accept": 'application/json'
            },
            "body": buffer
        };
        var opt = {
            service: 'pulsapi',
            scope: 'dl1-request',
            solution: 'region',
            accessKeyId: 'AKID',
            secret: 'TEST'
        };

        describe('Invalid payload', function () {
            it('Should throw Error', function () {
                let signer = new DLSigner(opt);
                expect(function () {
                    signer.sign(invalidPayload)
                }).to.throw();
            });
        });
        describe('Valid payload', function () {
            it('Should not throw Error', function () {
                let signer = new DLSigner(opt);
                expect(function () {
                    signer.sign(request)
                }).not.to.throw();
            });
            it('Should return correct hash', function () {
                let signer = new DLSigner(opt);
                const testHash = '9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08'.toLowerCase(); // 'test' sha256 hash
                expect(signer._hash(request.body, true, true)).to.equal(testHash);
            });
        });
        describe('Canonical Request', function () {
            it('Returns correct canonical request when request body is provided', function () {
                const signer = new DLSigner(opt);
                request.uri = '/examplebucket';
                const headers = request['headers'];
                const canonicalRequest = signer._prepareCanonicalRequest(
                    request['method'], signer._prepareCanonicalURI(request['uri']), signer._prepareCanonicalQueryString(request),
                    signer._prepareCanonicalHeaders(headers),
                    signer._prepareSignedHeaders(headers), signer._hash(request.body, true, true));
                let correctValue = 'POST\n' +
                    encodeURIComponent('/examplebucket') + '\n' +
                    '\n' +
                    'accept:application/json\n' +
                    'content-type:application/json\n' +
                    'host:test\n' +
                    'accept;content-type;host\n' +
                    '9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08'.toLowerCase();
                expect(canonicalRequest).to.equal(correctValue);
            });
        });
    });

});
