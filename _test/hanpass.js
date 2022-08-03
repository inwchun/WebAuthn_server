ITERATIONS = 100

async function newregistrationpw() {
    let resp = await window.fetch('server.php?fn=getCreateArgs' + getGetParams(), {method:'GET',cache:'no-cache'});
    let createCredentialArgs = await resp.json()
    recursiveBase64StrToArrayBuffer(createCredentialArgs);
    let AuthenticatorAttestationResponse = await create(createCredentialArgs);
    let json = {
        "id": AuthenticatorAttestationResponse.id,
        "clientDataJSON": arrayBufferToBase64(AuthenticatorAttestationResponse.response.clientDataJSON),
        "attestationObject": arrayBufferToBase64(AuthenticatorAttestationResponse.response.attestationObject)
    }
    let resp2 = await window.fetch('server.php?fn=processCreate' + getGetParams(), {method:'POST', body: JSON.stringify(json), cache:'no-cache'});
    let res = await resp2.json();
    if (res.success) {
        reloadServerPreview();
        window.alert(res.msg || 'registration success');
    } else {
        throw new Error(res.msg);
    }
}

async function checkregistrationpw() {
    let resp = await window.fetch('server.php?fn=getGetArgs' + getGetParams(), {method:'GET',cache:'no-cache'});
    let getCredentialArgs = await resp.json()
    recursiveBase64StrToArrayBuffer(getCredentialArgs);
    let AuthenticatorAttestationResponse = await get(getCredentialArgs);
    let json = {
        "id": arrayBufferToBase64(AuthenticatorAttestationResponse.rawId),
        "clientDataJSON": arrayBufferToBase64(AuthenticatorAttestationResponse.response.clientDataJSON),
        "authenticatorData": arrayBufferToBase64(AuthenticatorAttestationResponse.response.authenticatorData),
        "signature": arrayBufferToBase64(AuthenticatorAttestationResponse.response.signature),
        "userHandle": AuthenticatorAttestationResponse.response.userHandle // null
    }
    let resp2 = await window.fetch('server.php?fn=processGet' + getGetParams(), {method:'POST', body: JSON.stringify(json), cache:'no-cache'});
    console.log(resp2)
    let res = await resp2.json();
    console.log(res)
    if (res.success) {
        reloadServerPreview();
        window.alert(json.msg || 'login success');
    } else {
        throw new Error(json.msg);
    }

}

function strToArrayBuffer(str) {
    const encoder = new TextEncoder()
    return encoder.encode(str).buffer
}

function random(bytes) {
    return crypto.getRandomValues(new Uint8Array(bytes));
}

function xorBuffer(buf1, buf2, length) {
    let result = new Uint8Array(length)
    for(let i = 0; i < length; i++) {
        result[i] = buf1[i]^buf2[i];
    }
    return result;
}

function base64ToJSON(base64str) {
    return JSON.parse(atob(base64str))
}

function JSONToBase64(json) {
    return btoa(JSON.stringify(json))
}

function JSONToArrayBuffer(json) {
    return btoa(JSON.stringify(json))
}

async function createCredentials(password){
    let ks = random(32);
    let hpw = new Uint8Array(await (crypto.subtle.digest('SHA-256', strToArrayBuffer(password))));
    let credId = xorBuffer(ks, hpw, 32);
    let x = await pbkdf2(ks, ITERATIONS, 32)
    let pubkey = getPubkey(x);
    return [credId, pubkey]
}

function buf2hex(intArray) {
    return [...intArray].map(x => x.toString(16).padStart(2, '0')).join('');
}

function hex2buf(hex) {
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) {
        return parseInt(h, 16)
    }))
}


async function pbkdf2(ks, iterations=1e6, bytes=64, salt="0000000000000000") {
    const pwKey = await crypto.subtle.importKey('raw', ks, 'PBKDF2', false, ['deriveBits']); // create pw key
    // const saltUint8 = new Uint8Array(_base64ToArrayBuffer(salt));                             // get random salt;
    const saltUint8 = new TextEncoder().encode(salt);                             // get random salt;
    // dummy 16 byte salt
    const params = { name: 'PBKDF2', hash: 'SHA-512', salt: saltUint8, iterations: iterations }; // pbkdf2 params
    const keyBuffer = await crypto.subtle.deriveBits(params, pwKey, bytes*8);                        // derive key
    return new Uint8Array(keyBuffer);                                                                  // return composite key
}

/*
KJUR.crypto.ECParameterDB.regist(
  "secp256r1", // name / p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
  256,
  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", // p
  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", // a
  "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", // b
  "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", // n
  "1", // h
  "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", // gx
  "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", // gy
  ["NIST P-256", "P-256", "prime256v1"]); // alias

*/

// function keygen() {
//     let ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
// 	var biN = ec.ecparams['n'];
// 	var biPrv = ec.getBigRandom(biN);
// 	var charlen = ec.ecparams.keycharlen;
// 	var hPrv = ("0000000000" + biPrv.toString(16)).slice(- charlen);
// 	ec.setPrivateKeyHex(hPrv);
// 	var hPub = ec.generatePublicKeyHex();
// 	return {'ecprvhex': hPrv, 'ecpubhex': hPub};
// };

function getPubkey(seed) {
    let privkey = new KJUR.crypto.ECDSA({'curve': 'secp256r1', 'prv': buf2hex(seed)});
    let pubkey = new KJUR.crypto.ECDSA({'curve': 'secp256r1', 'pub': privkey.generatePublicKeyHex()});
    return KEYUTIL.getJWK(pubkey)
}

function getPrivkey(seed) {
    let privkey = new KJUR.crypto.ECDSA({'curve': 'secp256r1', 'prv': buf2hex(seed)});
    privkey.generatePublicKeyHex();
    return KEYUTIL.getJWK(privkey)
}


async function getWebcryptoKey(pubkey) {
    let key = await crypto.subtle.importKey(
        "jwk",
        testjson,
        {"name": "RSASSA-PKCS1-v1_5", "hash": "SHA-256"},
        true,
        ["verify"]
    )
    return key;
}

async function get(getCredentialArgs, origin = "https://sflab.snu.ac.kr:98", Sameoriginwithancestors = true) {
    let password = "password";
    let credIdBuffer = new Uint8Array(getCredentialArgs.publicKey.allowCredentials[0].id);  // assume only one
    let credIdBase64URL = base64ToBase64URL(_arrayBufferToBase64(credIdBuffer.buffer));
    let privkey = await getCredentials(password, credIdBuffer)
    // rpId may be replaced to origin's effective domain
    let originHost = new URL(origin).hostname
    let authenticatorData = await getAuthData(originHost)
    let clientDataJSON = getClientDataJSON(getCredentialArgs.publicKey.challenge, origin, Sameoriginwithancestors, "get")
    let clientDataHash = new Uint8Array(await (crypto.subtle.digest('SHA-256', clientDataJSON)));
    let msg = new Uint8Array([...(new Uint8Array(authenticatorData)), ...clientDataHash]);
    let signature = await sign(privkey, msg);
    return {
        "id": credIdBase64URL,
        "rawId": credIdBuffer.buffer,
        "response": {
            "authenticatorData": authenticatorData,
            "clientDataJSON": clientDataJSON,
            "signature": signature,
            "userHandle": null,
        }
    }
}

async function sign(privkey, msg) {
    const key = await crypto.subtle.importKey(
        "jwk",
        privkey,
        {"name": "ECDSA", "namedCurve": "P-256"},
        false,
        ["sign"]
    )

    const signature = await crypto.subtle.sign(
        {"name": "ECDSA", "hash": "SHA-256"},
        key,
        msg.buffer
    );
    console.log(arrayBufferToBase64(signature))
    let key2 = KEYUTIL.getKey(privkey);
    const sig = new KJUR.crypto.Signature({'alg':'SHA256withECDSA'});
    sig.init(key2)
    let signature2 = hex2buf(sig.signHex(buf2hex(msg)))
    console.log(arrayBufferToBase64(signature2))
    return signature2
    // return signature
}

async function getCredentials(password, credId) {
    let hpw = new Uint8Array(await (crypto.subtle.digest('SHA-256', strToArrayBuffer(password))));
    let ks = xorBuffer(credId, hpw, 32);
    let x = await pbkdf2(ks, ITERATIONS, 32)
    let privkey = getPrivkey(x);
    return privkey;
}

async function create(createCredentialArgs, origin = "https://sflab.snu.ac.kr:98", Sameoriginwithancestors = true) {
    let password = "password";
    let [credId, pubkey] = await createCredentials(password)
    let clientDataJSON = getClientDataJSON(createCredentialArgs.publicKey.challenge, origin, Sameoriginwithancestors, "create");
    let attestationObject = await getAttestationObject(createCredentialArgs.publicKey.rp.id, credId, pubkey)
    /*
        authData ->
        rpid hash: 32
        flag: 1 0x40=attestedcredentialdata 0x80=extensions
        counter: 4
        attestedCredentialData: Var
        extensions: Var

        attestedCredentialData ->
        aaguid: 16
        credentialIdLength: 2
        credentialId: L
        credentialPublicKey: Var (COSEpublickey)
    */
    return {
        "id" : base64ToBase64URL(arrayBufferToBase64(credId)),
        "rawId" : credId.buffer,
        "response" : {
            "attestationObject": attestationObject,
            "clientDataJSON": clientDataJSON
        },
        "type": "password"
    };
}

function getClientDataJSON(challenge, origin, Sameoriginwithancestors, type) {
    let json = {
        "type":"webauthn." + type,
        "challenge": base64ToBase64URL(arrayBufferToBase64(challenge)),
        "origin": origin,
        "crossOrigin": !Sameoriginwithancestors
    }
    return strToArrayBuffer(JSON.stringify(json))
}

async function getAttestationObject(rp, credId, pubkey) {
    let json = { // ArrayBuffer(390)
        "fmt":"none",
        "attStmt" : {},
        "authData": await getAuthData(rp, credId, pubkey, "create"),
    }
    return CBOR.encode(json)
}

async function getAuthData(rp, credId, pubkey, type="get") {
    let rpId = new Uint8Array(await crypto.subtle.digest('SHA-256', strToArrayBuffer(rp)));
    let flagNum = type=="get" ? 5 : 69; // credential data flag on for create
    let flag = new Uint8Array([flagNum]);
    let counter = new Uint8Array(4); // counter set to 0
    let attestedCredentialData = type=="get" ? new Uint8Array(0) : getAttestedCredentialData(credId, pubkey)
    // empty extensions
    return new Uint8Array([...rpId, ...flag, ...counter, ...attestedCredentialData]);
}

function getAttestedCredentialData(credId, pubkey) {
    let aaguid = new Uint8Array(16); // aaguid set to 0
    let credentialIdLength = new Uint8Array([0, 32]) // credId length 32 bytes
    let credentialId = new Uint8Array(credId)
    let credentialPublicKey = getCOSEEncode(pubkey)
    return new Uint8Array([ ...aaguid, ...credentialIdLength, ...credentialId, ...credentialPublicKey]);
}

function getCOSEEncode(pubkey) {
    let json = {
        "1": 2,   // public key EC2 format
        "3": -7,  // COSEAlgorithmIdentifier ES256
        "-1": 1,  // curve is P256
        "-2": new Uint8Array(window.base64url.decode(pubkey.x)),
        "-3": new Uint8Array(window.base64url.decode(pubkey.y))
    }
    return new Uint8Array(CBOR.encode(json))
}

function base64ToBase64URL(str) {
    return str.replace(/\+/g,'-').replace(/\//g,'_').replace(/\=+$/m,'');
}


function _base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function _arrayBufferToBase64( buffer ) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa( binary );
  }