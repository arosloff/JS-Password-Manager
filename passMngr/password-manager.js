"use strict";

/********* External Imports ********/

const { byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Implementation ********/
let globalSalt = genRandomSalt();

class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */

    // constructor takes in arguments and arguments go inside this.data and this.secrets
  constructor(derivedKey, hmacKey, aesKey, salt) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */

        // salt, integrity checks like checksum (trustedDataCheck)
//        this.salt = salt;
        'kvs': {},
        'iv' : {},
        'salt': salt

    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */

         // derivedkey for HMAC and AES
        // can also store master password here
        'derivedKey' : derivedKey,
        'hmacKey' : hmacKey,
        'aesKey' : aesKey

    };

    this.data.version = "CS 255 Password Manager v1.0";
    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;

      // initialize KVS
//    this.keychain = {}; // hmac(domain):aes(password)
  };

  /**
    * Creates an empty keychain with the given password. Once the constructor
    * has finished, the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {

	let salt = globalSalt

    let keyMaterial = await subtle.importKey("raw", password, {'name': "PBKDF2"}, false, ["deriveKey"]);

    let derivedKey = await subtle.deriveKey(
    	{
    		"name": "PBKDF2",
        	"salt": salt,
        	"iterations": this.PBKDF2_ITERATIONS,
        	"hash": "SHA-256"
      	},
      	keyMaterial,
      	{ "name": "HMAC", "hash": "SHA-256", "length": 256 },
      	false,
      	["sign"]
    );

    let aes_key_material = await subtle.sign('HMAC', derivedKey, 'AES-GCM');

    let hmac_key_material = await subtle.sign('HMAC', derivedKey, 'HMAC');

    let hmacKey = await subtle.importKey(
        "raw",
    	hmac_key_material,
    	{"name": "HMAC", "hash": "SHA-256", "length": 256},
		false,
    	["sign", "verify"]
    );

    let aesKey = await subtle.importKey("raw", aes_key_material, {'name': "AES-GCM"}, false, ["encrypt", "decrypt"]);

    let myKeychain = new Keychain(derivedKey, hmacKey, aesKey, salt); // save in this.data

    return myKeychain;

  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {

      if (trustedDataCheck != null) {
          let hash = JSON.stringify(await subtle.digest("SHA-256", repr));
		  hash = JSON.stringify(untypedToTypedArray(bufferToUntypedArray(hash)))
		  trustedDataCheck = JSON.stringify(untypedToTypedArray(bufferToUntypedArray(trustedDataCheck)))
          if (hash != trustedDataCheck) throw 'Mismatch!';
      }

	  let data = JSON.parse(repr)
	  let myKeychain = await Keychain.init(password)

	  myKeychain.data['kvs'] = data['kvs']
	  myKeychain.data['iv'] = data['iv']
	  myKeychain.data['salt'] = data['salt']

      return myKeychain;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */
  async dump() {
      if (this.ready == false) {
          return null;
      }

     var encoding = JSON.stringify(this.data); // this.myKeychain.{name}
     var checksum = JSON.stringify(bufferToUntypedArray(await subtle.digest("SHA-256", encoding)));

     return [encoding, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {

    if (this.ready == false) throw 'Keychain not initialized';

    let signature = bufferToUntypedArray(await subtle.sign("HMAC", this.secrets.hmacKey, name));
 	if (signature in this.data["kvs"]) { // syntax
    	var aesValue_untyped = this.data.kvs[signature];

        var AES_dict = {
      		'name': 'AES-GCM',
            'iv': this.data.iv[signature],
            'additionalData': untypedToTypedArray(signature)
         };

         var aesValue_typed = untypedToTypedArray(aesValue_untyped)

         let result = await subtle.decrypt(AES_dict, this.secrets.aesKey, aesValue_typed)

         return byteArrayToString(result).replace(/\0/g, '')

	 }
     else return null;
  };

  /**
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
      if (this.ready == false) throw "Keychain not initialized";

      var iv = genRandomSalt();

      let signature = bufferToUntypedArray(await subtle.sign("HMAC", this.secrets.hmacKey, name));

      var AES_dict = {
          'name': 'AES-GCM',
          'iv': iv,
          'additionalData': untypedToTypedArray(signature) // swap attack
      };

	  let newValue = value
	  var diff = 64 - value.length
	  for (let i = 0; i < diff; i++) newValue = newValue.concat('\0')

      let aesValue = await subtle.encrypt(AES_dict, this.secrets.aesKey, newValue); // aes key

      var aesValue_untyped = bufferToUntypedArray(aesValue)
      this.data.iv[signature] = iv;

      this.data.kvs[signature] = aesValue_untyped;
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {

      if (this.ready == false) {
          throw "Keychain not initialized"
      }

      let signature = bufferToUntypedArray(await subtle.sign(
        "HMAC",
        this.secrets.hmacKey, // hmac key
        name
      ));

      if (this.data.kvs.hasOwnProperty(signature)) {
          delete this.data.kvs[signature]
          return true
      }
      return false

  };

  static get PBKDF2_ITERATIONS() { return 100000; }
};

module.exports = {
  Keychain: Keychain
}
