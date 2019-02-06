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
                    '267247df1f154aefc4d27033245fa55cb8abb31f48a85ba55ebfaf82aec4a187';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Correct Authorization header for request with query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    'ca334d74f2c3b9cc0415b9383966ac1e3c18bd43d9941c5ecdfe272a90aec8f0';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });

            it('Should return correct X-DL-Date header', function () {
                var correctDate = '19700101T010000Z';
                expect(signer.sign(request)['X-DL-Date']).to.equal(correctDate);
            });
        });
        describe('Correct Authorization header for request with unsorted query parameters without value', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test?Zzz&aaa&Aaa';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    'ba2bc6a87afbff9e4fdcca768ce75e1c07808aaa45863c73387556f43473142f';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with unsorted query parameters without value', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test?Zzz&aaa=B&Aaa';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    'ebfa4276ec80c405cf24d8c5b0816449309427a50cfbd3975a8894aea9d6fdbc';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with whitespace in query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test/test2?Zzz&aaa=B&Aaa= aw';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    '9e5bc2455a134e86095e7fb631c57d84b2d6c7c8b3db3c0e9ecac96a9068af62';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });

        describe('Correct Authorization header for request with unreserved characters query string', function () {
            it('Should return correct SHA256 hash for given request', function () {
                request.uri = '/test/test2?Zzz&aaa=B&Aaa= /aw';

                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;x-dl-date,Signature=' +
                    '2ce30a1edcc686c79b816189c653be1c980a850c04140cbdbde3d2572f62041a';
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
                    'bfcf0da0eaeb312f4d4164685996cdb319c57993700a9d0b398b3c5da4da40291e0a25a695752ba08b05019c6b24caec7e9862820bfca149a29be40ee2f4583f';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
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
                    '0e45160526c02e432cf2b08988a4ae1341cc9a608da5efe330397f581bf32bc2';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Request with additional header', function () {
            it('Should return correct signature', function () {
                request.headers.test = 'test';
                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;test;x-dl-date,Signature=' +
                    'f9bdf85e5226b3889098e799e65bd21cdbb22443893460c2ed050f8ca7b8dabb';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
        describe('Request with whitespaces in header value', function () {
            it('Should return the same signature as without them', function () {
                request.headers.test = '    test  ';
                var correctHash = 'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                    'accept;content-type;host;test;x-dl-date,Signature=' +
                    'f9bdf85e5226b3889098e799e65bd21cdbb22443893460c2ed050f8ca7b8dabb';
                expect(signer.sign(request)['Authorization']).to.equal(correctHash);
            });
        });
    });
});
