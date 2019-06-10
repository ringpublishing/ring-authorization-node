var expect = require('chai').expect;

var DLSigner = require('../index').DLSigner;

describe('RingAuthorization', function () {
    Date.now = function () {
        return 0;
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
                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    '449e1e282ecd448c5893759c274cbfaa857e41b3a48c4c992178fedb1aabc2d5';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Correct Authorization header for request with query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    'b45ff133934c1cfc1cccb9e52fd57dec5b8860c2f3a2e84483b1f6ea119a004d';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });

            it('Should return correct X-DL-Date header', function () {
                var correctDate = '19700101T000000Z';
                expect(signer.sign(request)['X-DL-Date']).to.equal(correctDate);
            });
        });
        describe('Correct Authorization header for request with unsorted query parameters without value', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test?Zzz&aaa&Aaa';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    '6d9fca6bb4ea9201a604101416c24cb8e859e20dbd3b236e6d154ca2749505db';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with unsorted query parameters without value', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test?Zzz&aaa=B&Aaa';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    '84527c0c2a93dd9d997ff35858aa82470daa1ad654d9885cb48eafa1dd4d3944';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with whitespace in query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test/test2?Zzz&aaa=B&Aaa= aw';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    '9a6016743b2883e54cd8df0415b82098d3b895a1725e2b83c2733ff55cf965f3';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with unreserved characters query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test/test2?Zzz&aaa=B&Aaa= /aw';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    'b96cf237a16906c356ed940e4bf17180d75709056950db7510db499947894e2e';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with SHA-512 hash', function () {
            it('Should return correct SHA512 hash for given request', function () {
                opt.algorithm = 'DL-HMAC-SHA512';
                signer = new DLSigner(opt);
                request.uri = '/test/test2?Zzz&aaa=B&Aaa= /aw.~~';

                var correctHash = 'DL-HMAC-SHA512 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    '1019ea80dd07797359d0d67925c429cac0c9ae0be34640821f3e84b4ff931cae1370da3041e566f8d9c9c6d11ab9e817366bd05d3e1a680e041dd32390e0aaa3';
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
                var correctDateString = '19900101T000000Z';
                request.headers['X-DL-Date'] = correctDateString;
                expect(signer.sign(request)['X-DL-Date']).to.equal(correctDateString);
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
                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    'f58b69896948e8c4ad16870deeec536b7ebf8bf5a3bac45fb3a69aa76294c802';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Request with additional header', function () {
            it('Should return correct signature', function () {
                request.headers.test = 'test';
                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;test;x-dl-date,Signature=' +
                    'aebb432375c15fe1c57fd4b82d755358a4c48dca050a3261fadbe37d61557e5e';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Request with whitespaces in header value', function () {
            it('Should return the same signature as without them', function () {
                request.headers.test = '    test  ';
                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;test;x-dl-date,Signature=' +
                    'aebb432375c15fe1c57fd4b82d755358a4c48dca050a3261fadbe37d61557e5e';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
    });
});
