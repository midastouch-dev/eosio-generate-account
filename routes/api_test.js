let express = require('express');
let router = express.Router();
const bip39 = require('bip39');
const ecc = require('eosjs-ecc');

/**
 * get the seed phrases of 12 words
 *
 * @param
 * @return object If success returns seed phrases else returns error message
 *  code: result code
 *  message: result message
 *  seed: seed phrase of 12 words
 * 
 */
router.get('/seed', function(req, res) {
    const mnemonic = bip39.generateMnemonic();
    
    res.json({
        code: 200,
        message: 'success',
        seed: mnemonic,
    });
});

/**
 * get the public and private key
 *
 * @param seed: seed phrases of 12 words
 * @return  object If success returns key pair else returns error message
 *  code: result code
 *  message: result message
 *  key: public & private key pair 
 *  
 */
router.post('/keys', function(req, res) {
    if(!req.body || !req.body.seed || req.body.seed.split(' ').length != 12) {
        res.json({
            code: 400,
            message: 'the parameter is failed',
        });
        return;
    }
    
    const key_pri = ecc.seedPrivate(req.body.seed);
    const key_pub = ecc.privateToPublic(key_pri);

    res.json({
        code: 200,
        message: 'success',
        key: {
            public: key_pub,
            private: key_pri,
        },
    });
});

/**
 * validate the public key
 *
 * @param key: public key
 * @return  object If success returns success else returns failed
 *  code: result code
 *  message: result message
 *  
 */
 router.post('/validate/pubkey', function(req, res) {
    if(!req.body || !req.body.key) {
        res.json({
            code: 400,
            message: 'the parameter is failed',
        });
        return;
    }
    
    if(ecc.isValidPublic(req.body.key)) {
        res.json({
            code: 200,
            message: 'success',
        });
    } else {
        res.json({
            code: 200,
            message: 'failed',
        });
    }
});


/**
 * validate the private key
 *
 * @param key: private key
 * @return  object If success returns success else returns failed
 *  code: result code
 *  message: result message
 *  
 */
 router.post('/validate/prikey', function(req, res) {
    if(!req.body || !req.body.key) {
        res.json({
            code: 400,
            message: 'the parameter is failed',
        });
        return;
    }
    
    if(ecc.isValidPrivate(req.body.key)) {
        res.json({
            code: 200,
            message: 'success',
        });
    } else {
        res.json({
            code: 200,
            message: 'failed',
        });
    }
});

module.exports = router;