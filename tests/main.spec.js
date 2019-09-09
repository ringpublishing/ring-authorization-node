var expect = require('chai').expect;

var DLSigner = require('../index').DLSigner;

describe('RingAuthorization', function () {
    Date.now = function () {
        return 1462361249000;
    };
    Date.prototype.getTime = Date.now;

    describe('GET request', function () {
        var opt = {
            service: 'pulsapi',
            accessKey: 'test',
            secretKey: 'test'
        };
        var signer = new DLSigner(opt);

        var request = {
            "method": "GET",
            "uri": '/test',
            "headers": {
                "host": 'test',
                "content-type": 'application/json',
                "accept": 'application/json'
            }
        };

        describe('Invalid algorithm', function () {
            it('Should throw Error', function () {
                var invalidOpt = {
                    algorithm: 'TEST'
                };
                expect(function () {
                    new DLSigner(invalidOpt)
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


        describe('Correct Authorization header for request without query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;x-dl-date,Signature=7a0a9f2bd6c53fce7b57afafd33abf0a7afd37c829dc032d858a53697438e817';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Correct Authorization header for request with query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;x-dl-date,Signature=594d74f39110c9becb78cc3ed02ab443ad5056b913b0421fadb6767d73cadf66';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });

            it('Should return correct X-DL-Date header', function () {
                var correctDate = '20160504T112729Z';
                expect(signer.sign(request)['X-DL-Date']).to.equal(correctDate);
            });
        });
        describe('Correct Authorization header for request with unsorted query parameters without value', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test?Zzz&aaa&Aaa';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;x-dl-date,Signature=61c559989f2e83bfab4a522f32bceb5fa51b9bc3f738d4c6cc7702de18887023';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with unsorted query parameters without value', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test?Zzz&aaa=B&Aaa';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;x-dl-date,Signature=a062166eb9f75d0d6d36d9f20298385ca89b69a58bb686bb3a489eb762346956';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with whitespace in query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test/test2?Zzz&aaa=B&Aaa= aw';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;x-dl-date,Signature=4780cddf22ef264287e38c7625928fbbc2fe7d02d3616475f8a94e914784a38c';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with unreserved characters query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test/test2?Zzz&aaa=B&Aaa= /aw';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;x-dl-date,Signature=58077cf153f30c9b71459ca339b3f989f6ca4cc86e41e36627d7f46b0a01c7b1';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with SHA-512 hash', function () {
            it('Should return correct SHA512 hash for given request', function () {
                opt.algorithm = 'DL-HMAC-SHA512';
                signer = new DLSigner(opt);
                request.uri = '/test/test2?Zzz&aaa=B&Aaa= /aw.~~';

                var correctHash = 'DL-HMAC-SHA512 Credential=test/20160504/RING/pulsapi/dl1_request' +
                    ',SignedHeaders=accept;content-type;host;x-dl-date,Signature=08f825823e9552835ec69eba84e278993c1af8a8f09c36f2a13a9e526b8c47f84a755ee3644f6ead247895386256425c34f98bf1ea4e897ad15dc995438ad60f';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Invalid date', function () {
            it('Should throw Error when date is a string', function () {
                request.headers['X-DL-Date'] = 'incorrect date';
                expect(function () {
                    signer.sign(request)
                }).to.throw();
            });
            it('Should throw Error when date is a not complete date', function () {
                request.headers['X-DL-Date'] = '1990010';
                expect(function () {
                    signer.sign(request)
                }).to.throw();
            });
            it('Should not throw any Error when date is a valid date', function () {
                request.headers['X-DL-Date'] = '20160504T000000Z';

                var correctDateString = '20160504T000000Z';
                var correctDateStamp = '20160504';
                request.headers['X-DL-Date'] = correctDateString;

                var signedRequest = signer.sign(request);
                expect(signedRequest['X-DL-Date']).to.equal(correctDateString);
                var requestDatestamp = signedRequest['Authorization'].split('/')[1];
                expect(requestDatestamp).to.equal(correctDateStamp);
            });
        });
    });

    describe('POST request', function () {
        var request = {
            "method": "POST",
            "uri": '/test',
            "headers": {
                "host": 'test',
                "content-type": 'application/json',
                "accept": 'application/json'
            },
            "body": new Buffer('test')
        };
        var opt = {
            service: 'pulsapi',
            accessKey: 'test',
            secretKey: 'test'
        };

        var signer = new DLSigner(opt);

        describe('Request not with byte payload', function () {
            it('Should throw Error', function () {
                var requestWithInvalidPayload = {
                    "method": "POST",
                    "uri": '/test',
                    "headers": {
                        "host": 'test',
                        "content-type": 'application/json',
                        "accept": 'application/json'
                    },
                    "body": 'test'
                };
                expect(function () {
                    signer.sign(requestWithInvalidPayload)
                }).to.throw();
            });
        });
        describe('Request with payload', function () {
            it('Should return correct signature', function () {
                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;x-dl-date,Signature=40bb40619c065369991fb80afb64c2669fb3aeffe6a6da55c2d7b910934fddf9';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Request with additional header', function () {
            it('Should return correct signature', function () {
                request.headers.test = 'test';
                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;test;x-dl-date,Signature=2e16b5fcdb7a502ee5b3ea3471eb31cf29a58e4059a50c90f44761694614e3e6';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Request with whitespaces in header value', function () {
            it('Should return the same signature as without them', function () {
                request.headers.test = '    test  ';
                var correctHash = 'DL-HMAC-SHA256 Credential=test/20160504/RING/pulsapi/dl1_request,' +
                    'SignedHeaders=accept;content-type;host;test;x-dl-date,Signature=2e16b5fcdb7a502ee5b3ea3471eb31cf29a58e4059a50c90f44761694614e3e6';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
    });
});
