let express = require('express');
let router = express.Router();
const bip39 = require('bip39');
const ecc = require('eosjs-ecc');
const { Api, JsonRpc } = require('eosjs');
const { JsSignatureProvider } = require('eosjs/dist/eosjs-jssig');  // development only
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
// const fetch = require('node-fetch');
const { TextDecoder, TextEncoder } = require('util');
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

/**
 * Generate new account
 *
 * @param 
 *  name: new account name
 *  key: private key
 * @return  object If success returns success else returns failed
 *  code: result code
 *  message: result message
 *  
 */
 router.post('/account', async function(req, res) {
    if(!req.body || !req.body.key || !req.body.account) {
        res.json({
            code: 400,
            message: 'the parameter is failed',
        });
        return;
    }

    const privateKeys = [process.env.EOS_PRIVATE_KEY];
    const signatureProvider = new JsSignatureProvider(privateKeys);
    const rpc = new JsonRpc(process.env.EOS_SERVER_URL, { fetch });
    const api = new Api({ rpc, signatureProvider, textDecoder: new TextDecoder(), textEncoder: new TextEncoder() });

    const new_pub_key = req.body.key;
    const new_account = req.body.account;

    try{
        await api.transact({
            actions: [{
              account: 'eosio',
              name: 'newaccount',
              authorization: [{
                actor: 'eosio',
                permission: 'active',
              }],
              data: {
                creator: 'eosio',
                name: new_account,
                owner: {
                  threshold: 1,
                  keys: [{
                    key: new_pub_key,
                    weight: 1
                  }],
                  accounts: [],
                  waits: []
                },
                active: {
                  threshold: 1,
                  keys: [{
                    key: new_pub_key,
                    weight: 1
                  }],
                
                  accounts: [],
                  waits: []
                },
              },
            }]
          }, {
            blocksBehind: 3,
            expireSeconds: 30,
          });
    } catch(e) {
        console.log(e)
        res.json({
            code: 501,
            message: 'Failed to create account',
        })
    }

    res.json({
        code: 200,
        message: 'success',
    });
});

/**
 * Get new account
 *
 * @param 
 *  name: account name
 * @return  object If success returns account info else returns failed
 *  code: result code
 *  message: result message
 *  data: account
 */
 router.get('/account', async function(req, res) {
    if(!req.query || !req.query.account) {
        res.json({
            code: 400,
            message: 'the parameter is failed',
        });
        return;
    }
    
    const rpc = new JsonRpc(process.env.EOS_SERVER_URL, { fetch });

    try{
        const account = await rpc.get_account(req.query.account);
        res.json({
            code: 200,
            message: 'success',
            data: account
        })
    } catch(e) {
        console.log(e)
        res.json({
            code: 501,
            message: 'Failed to get account',
        })
    }
});

module.exports = router;