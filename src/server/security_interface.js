const {PythonShell} = require('python-shell');
var crypto = require('crypto');
var async = require("async")
SECURITY_MODULE_PATH = '../security/security.py'

function runPython(script, args) {
    return new Promise((resolve, reject) => {
        PythonShell.run(script, {args}, function (err, results) {
            if(err) {
                console.log(err)
                reject(err)
            }
            resolve(JSON.parse(results))
        })
    })
}

/////////////// HASHING ALGORITHMS ///////////////
async function hash_sha256(R1,R2,deck){
    return await runPython(SECURITY_MODULE_PATH,['hash','sha256',R1,R2,deck.join(':')])
}

///////////////SYMMETRIC ENCRYPTION AND DECRYPTION///////////////
async function sym_encrypt(password,cleartext,algorithm,mode){
    return await runPython(SECURITY_MODULE_PATH,['sym','encrypt',password,cleartext,algorithm,mode])
}

async function sym_decrypt(password,ciphertext,algorithm,mode){
    return await runPython(SECURITY_MODULE_PATH,['sym','decrypt',password,ciphertext,algorithm,mode])
}

///////////////RSA ENCRYPTION AND DECRYPTION///////////////
async function rsa_generate_key_pair(password){
    return await runPython(SECURITY_MODULE_PATH,['rsa','generate_key_pair',password])
}

async function rsa_encrypt(publicKey,cleartext){
    return await runPython(SECURITY_MODULE_PATH,['rsa','encrypt',publicKey,cleartext])
}

async function rsa_decrypt(password,privateKey,ciphertext){
    return await runPython(SECURITY_MODULE_PATH,['rsa','decrypt',password,privateKey,ciphertext])
}

///////////////RSA SIGN AND VERIFY SIGNATURE///////////////

async function rsa_sign(password,privateKey,message){
    // return await runPython(SECURITY_MODULE_PATH,['rsa','sign',password,privateKey,message])
    privateKey = decodeBase64(privateKey)
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(message);
    signer.end();
    privateKey = crypto.createPrivateKey({
        key: privateKey,
        format: 'pem',
        type: 'pkcs8',
        // cipher: 'aes-256-cbc',
        passphrase: password
    });
    const signature = signer.sign({
        key:privateKey,
        // dsaEncoding,
        padding:crypto.constants.RSA_PKCS1_PSS_PADDING,
        // saltLength,
    },'base64')
    // console.log(signature)
    return {algorithm:'rsa',function:'sign',signature}
}

async function rsa_verify(publicKey,signature,message){
    return await runPython(SECURITY_MODULE_PATH,['rsa','verify',publicKey,signature,message])
}

async function rsa_verify_signed_certificate(certificate,original_message,signature){
    return await runPython(SECURITY_MODULE_PATH,['rsa','verify_signed_certificate',certificate,original_message,signature])
}

async function rsa_verify_chain_of_trust(certificate){
    return await runPython(SECURITY_MODULE_PATH,['citizen_card','verify_chain_of_trust',certificate])
}

function encodeBase64(str){
    return (Buffer.from(str)).toString('base64');
}

function decodeBase64(str){
    return (Buffer.from(str, 'base64')).toString('ascii');
}

module.exports = {
    sym_encrypt,
    sym_decrypt,
    rsa_generate_key_pair,
    rsa_encrypt,
    rsa_decrypt,
    encodeBase64,
    decodeBase64,
    rsa_sign,
    rsa_verify,
    rsa_verify_signed_certificate,
    rsa_verify_chain_of_trust,
    hash_sha256,
};


////////////////// TESTING /////////////////

function generate_random_string(length){
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < length; i++)
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    return text;
}

async function runTests(N){
    for(var i = 0; i < N; i++){
        test(i)
    }
}

async function test(i){
    // //Testing AES
    var aes_password = generate_random_string(100)
    var aes_cleartext = 'random string to encrypt with aes'
    var res = {aes_password,i,...await sym_encrypt(aes_password, aes_cleartext)}
    console.log(res)
    res = {aes_password,i,...await sym_decrypt(aes_password,res.ciphertext)}
    console.log(res)

    //Testing RSA
    var rsa_password = generate_random_string(100)
    var rsa_cleartext = 'rsa string test'
    var key_pair = {rsa_password,i,...await rsa_generate_key_pair(rsa_password)}
    console.log(key_pair)
    var res = {rsa_password,i,...await rsa_encrypt(key_pair.publicKey,rsa_cleartext)}
    console.log(res)
    res = {rsa_password,i,...await rsa_decrypt(rsa_password,key_pair.privateKey,res.ciphertext)}
    console.log(res)

    //Testing signing and verifying
    res = {rsa_password,i,...await rsa_sign(rsa_password,key_pair.privateKey,rsa_cleartext)}
    console.log(res)
    res = {rsa_password,i,...await rsa_verify(key_pair.publicKey,res.signature,rsa_cleartext)}
    console.log(res)
    if(!res.valid){
        console.log('Test failed. Invalid signature!')
        process.exit(1)
    }
}