package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"strconv"

	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

const BASE_KEYLEN = 16

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func pad(blocksize int, msg []byte) (ret []byte) {

	for i := 0; i < len(msg); i++ {
		ret = append(ret, msg[i])
	}

	// how many bytes are missing to make msg a multiple a of block size
	var blocks = int(len(msg) / blocksize)
	var missing = (blocks+1)*blocksize - len(msg)

	for i := 0; i < missing; i++ {
		ret = append(ret, byte(missing))
	}
	return ret
}

func unpad(blocksize int, msg []byte) (ret []byte) {

	if len(msg) <= 0 || len(msg)%blocksize != 0 {
		return msg
	}

	var last = int(msg[len(msg)-1])
	return msg[:len(msg)-last]
}

func encryptAndSign(encryptKey []byte, signKey []byte, msg []byte) (ret []byte, err error) {

	var encrypted = userlib.SymEnc(encryptKey, userlib.RandomBytes(16), pad(16, msg))

	ret, err = userlib.HMACEval(signKey, encrypted)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Checking integrity failed!"))
	}

	for i := 0; i < len(encrypted); i++ {
		ret = append(ret, encrypted[i])
	}
	return ret, nil
}

func verifyAndDecrypt(encryptKey []byte, signKey []byte, cipher []byte) (ret []byte, err error) {

	if len(cipher) <= 64 {
		return nil, errors.New(strings.ToTitle("Cipher is too short!"))
	}

	var hmac = cipher[:64]
	var userCipher = cipher[64:]

	check, err := userlib.HMACEval(signKey, userCipher)
	if err != nil || userlib.HMACEqual(check, hmac) == false {
		return nil, errors.New(strings.ToTitle("Checking integrity failed!"))
	}

	// encryptKey is symmetric, used for both encryption and decryption
	ret = userlib.SymDec(encryptKey, userCipher)
	return unpad(16, ret), nil
}

func (userdata *User) getFileMetadata(filename string) (meta FileMetaData, err error) {

	var metadata FileMetaData

	// the key in the datastore containing the key of the map
	// we'll use that key of the map to get an encrypted MapEntry that we'll decrypt
	var hashOfPtr = userlib.Hash([]byte("ptr/" + userdata.Username + "/" + filename))
	var pointerKey = bytesToUUID(hashOfPtr[:])

	pointerVal, ok := userlib.DatastoreGet(pointerKey)
	if ok == false {
		return metadata, errors.New(strings.ToTitle("Erased from Datastore!"))
	}

	ptrDecrypted, err := verifyAndDecrypt(userdata.encryptKey, userdata.signKey, pointerVal)
	if err != nil {
		return metadata, err
	}

	var keyToMeta uuid.UUID
	err = json.Unmarshal(ptrDecrypted, &keyToMeta)
	if err != nil {
		return metadata, errors.New(strings.ToTitle("Invalid key!"))
	}

	metaJSON, ok := userlib.DatastoreGet(keyToMeta)
	if ok == false {
		return metadata, errors.New(strings.ToTitle("Erased from Datastore!"))
	}

	err = json.Unmarshal(metaJSON, &metadata)
	if err != nil {
		return metadata, errors.New(strings.ToTitle("Invalid metadata!"))
	}

	return metadata, nil
}

// The structure definition for a user record
type User struct {
	// public
	Username    string
	PrivateDec  userlib.PKEDecKey
	PrivateSign userlib.DSSignKey
	// private
	publicDec  userlib.PKEEncKey
	publicSign userlib.DSVerifyKey
	baseKey    []byte
	encryptKey []byte
	signKey    []byte
}

// The entry of the sharing tree
type MapEntry struct {
	EntryKey   uuid.UUID // the key where the file is stored in the Datastore
	SymEncKey  []byte    // for encrypting/decrypting the file contents
	SymSignKey []byte    // for signing/verifying the file contents
	Children   []string  // the usernames of users that this user has shared the file to
}

type FileMetaData struct {
	Owner         string
	OwnerHMAC     []byte
	KeyToMetaData uuid.UUID
	SharingTree   map[string]MapEntry
	Appends       []uuid.UUID
}

type Token struct {
	Signature   []byte
	MetaDataKey uuid.UUID
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {

	// the key in the datastore, computed based on the username
	var hash = userlib.Hash([]byte("user/" + username))
	var key = bytesToUUID(hash[:])

	_, exists := userlib.DatastoreGet(key)
	if exists == true {
		return nil, errors.New(strings.ToTitle("User already exists"))
	}

	var userdata User
	userdataptr = &userdata

	userdata.Username = username

	// RSA keys for encryption/decryption and signing
	userdata.publicDec, userdata.PrivateDec, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	userdata.PrivateSign, userdata.publicSign, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// storing public keys inside the KeyStore
	err = userlib.KeystoreSet(username+"_enc", userdata.publicDec)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"_sign", userdata.publicSign)
	if err != nil {
		return nil, err
	}

	// TODO: play with the keyLen
	userdata.baseKey = userlib.Argon2Key([]byte(password), []byte(password), BASE_KEYLEN)

	// TODO: check for error?
	// the symmetric encryption key, need to be 16 bytes for HKDF
	userdata.encryptKey, err = userlib.HashKDF(userdata.baseKey, []byte("encrypt"))
	if err != nil {
		return nil, err
	}
	userdata.encryptKey = userdata.encryptKey[:16]

	// the symmetric signing key
	userdata.signKey, err = userlib.HashKDF(userdata.baseKey, []byte("sign"))
	if err != nil {
		return nil, err
	}
	userdata.signKey = userdata.signKey[:16]

	// pointer?
	json, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	value, err := encryptAndSign(userdata.encryptKey, userdata.signKey, json)
	if err != nil {
		return nil, err
	}

	// key = UUID("user/" + username)
	// value = HMAC + SymEnc(User)
	userlib.DatastoreSet(key, value)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

	var userdata User
	userdataptr = &userdata

	var baseKey = userlib.Argon2Key([]byte(password), []byte(password), BASE_KEYLEN)

	// the symmetric encryption key, need to be 16 bytes for HKDF
	encryptKey, err := userlib.HashKDF(baseKey, []byte("encrypt"))
	if err != nil {
		return nil, err
	}
	encryptKey = encryptKey[:16]

	// the symmetric signing key
	signKey, err := userlib.HashKDF(baseKey, []byte("sign"))
	if err != nil {
		return nil, err
	}
	signKey = signKey[:16]

	// the key in the datastore, computed based on the username
	var hash = userlib.Hash([]byte("user/" + username))
	var key = bytesToUUID(hash[:])

	cipher, ok := userlib.DatastoreGet(key)
	if ok == false {
		return nil, errors.New(strings.ToTitle("User doesn't exist"))
	}

	// encryptKey is symmetric, used for both encryption and decryption
	userDecrypted, err := verifyAndDecrypt(encryptKey, signKey, cipher)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(userDecrypted, &userdata)
	if err != nil {
		return userdataptr, errors.New(strings.ToTitle("Incorrect credentials"))
	}

	userdata.baseKey = baseKey
	userdata.encryptKey = encryptKey
	userdata.signKey = signKey

	userdata.publicDec, ok = userlib.KeystoreGet(username + "_enc")
	if ok == false {
		return nil, errors.New(strings.ToTitle("Public Key not found"))
	}

	userdata.publicSign, ok = userlib.KeystoreGet(username + "_sign")
	if ok == false {
		return nil, errors.New(strings.ToTitle("Public Key not found"))
	}

	return &userdata, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	// TODO: check if the user is authenticated
	// TODO: catch unauthorized modifications, compute checksum of file and metadata after each append/store

	// computing enc and sign keys based on the owner's enc and sign key
	// can't share encryptKey and signKey with other users, that's why create other keys using them
	fileEncKey, err := userlib.HashKDF(userdata.encryptKey, []byte(userdata.Username+"/"+filename))
	if err != nil {
		return
	}
	fileEncKey = fileEncKey[:16]

	fileSignKey, err := userlib.HashKDF(userdata.signKey, []byte(userdata.Username+"/"+filename))
	if err != nil {
		return
	}
	fileSignKey = fileSignKey[:16]

	/////////// Step 1 - store the file inside the Datastore

	value, err := encryptAndSign(fileEncKey, fileSignKey, data)
	if err != nil {
		return
	}

	// the key in the datastore for storing the file
	var hash = userlib.Hash([]byte("file/" + userdata.Username + "/" + filename))
	var key = bytesToUUID(hash[:])

	// found is referenced after overriding the Datastore
	_, found := userlib.DatastoreGet(key)

	// key = UUID("file/" + username + "/" + filename)
	// value = HMAC + SymEnc(data)
	userlib.DatastoreSet(key, value)

	// the file already exists
	// remove all the appends
	if found == true {
		metadata, err := userdata.getFileMetadata(filename)
		if err != nil {
			return
		}

		for i := 0; i < len(metadata.Appends); i++ {
			userlib.DatastoreDelete(metadata.Appends[i])
		}
		metadata.Appends = metadata.Appends[:0]

		metadataJSON, err := json.Marshal(metadata)
		if err != nil {
			return
		}

		// metadata.KeyToMetaData allows overriding the original metadata
		// since filename is different across users
		userlib.DatastoreSet(metadata.KeyToMetaData, metadataJSON)
		return
	}

	/////////// Step 2 - store the metafile of the file

	// the key in the datastore for storing the file
	var hashToMeta = userlib.Hash([]byte("meta/" + userdata.Username + "/" + filename))
	var keyToMeta = bytesToUUID(hashToMeta[:])

	var meta FileMetaData
	meta.KeyToMetaData = keyToMeta
	meta.Owner = userdata.Username
	// check for integrity of the owner whenever RevokeFile is called
	meta.OwnerHMAC, err = userlib.HMACEval(userdata.signKey, []byte(meta.Owner))
	if err != nil {
		return
	}

	meta.SharingTree = make(map[string]MapEntry)

	// encrypt the keys inside the entry using the public RSA key of the owner
	// because the entry contains keys for verifying and decrypting the file
	var entry MapEntry
	entry.EntryKey = key
	entry.SymEncKey, err = userlib.PKEEnc(userdata.publicDec, fileEncKey)
	if err != nil {
		return
	}

	entry.SymSignKey, err = userlib.PKEEnc(userdata.publicDec, fileSignKey)
	if err != nil {
		return
	}

	meta.SharingTree[userdata.Username] = entry

	metafileJSON, err := json.Marshal(meta)
	if err != nil {
		return
	}

	userlib.DatastoreSet(keyToMeta, metafileJSON)

	/////////// Step 3 - store the pointer to the map
	// makes sharing and revoking later on easier

	pointerValue, err := json.Marshal(keyToMeta)
	if err != nil {
		return
	}

	pointerValue, err = encryptAndSign(userdata.encryptKey, userdata.signKey, pointerValue)
	if err != nil {
		return
	}

	// the key in the datastore for storing the file
	var hashOfPtr = userlib.Hash([]byte("ptr/" + userdata.Username + "/" + filename))
	var pointerKey = bytesToUUID(hashOfPtr[:])

	// key = UUID("ptr/" + username + "/" + filename)
	// value = HMAC + SymEnc(UUID("meta/" + userdata.Username + "/" + filename))
	userlib.DatastoreSet(pointerKey, pointerValue)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	metadata, err := userdata.getFileMetadata(filename)
	if err != nil {
		return err
	}

	entry, ok := metadata.SharingTree[userdata.Username]
	if ok == false {
		return errors.New(strings.ToTitle("Doesn't have access to this file"))
	}

	_, ok = userlib.DatastoreGet(entry.EntryKey)
	if ok == false {
		return errors.New(strings.ToTitle("File doesn't exist"))
	}

	entry.SymEncKey, err = userlib.PKEDec(userdata.PrivateDec, entry.SymEncKey)
	if err != nil {
		return err
	}

	entry.SymSignKey, err = userlib.PKEDec(userdata.PrivateDec, entry.SymSignKey)
	if err != nil {
		return err
	}

	var index = len(metadata.Appends)
	var appendKeyName = userlib.Hash([]byte("file/" + userdata.Username + "/" + filename + strconv.Itoa(index)))
	var appendKey = bytesToUUID(appendKeyName[:])

	value, err := encryptAndSign(entry.SymEncKey, entry.SymSignKey, data)
	if err != nil {
		return err
	}

	// key = UUID("file/" + username + "/" + filename + appendIndex)
	// value = HMAC + SymEnc(data)
	userlib.DatastoreSet(appendKey, value)

	metadata.Appends = append(metadata.Appends, appendKey)
	metafileJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(metadata.KeyToMetaData, metafileJSON)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	metadata, err := userdata.getFileMetadata(filename)
	if err != nil {
		return nil, err
	}

	entry, ok := metadata.SharingTree[userdata.Username]
	if ok == false {
		return nil, errors.New(strings.ToTitle("Doesn't have access to this file"))
	}

	entry.SymEncKey, err = userlib.PKEDec(userdata.PrivateDec, entry.SymEncKey)
	if err != nil {
		return nil, err
	}

	entry.SymSignKey, err = userlib.PKEDec(userdata.PrivateDec, entry.SymSignKey)
	if err != nil {
		return nil, err
	}

	fileEncrypted, ok := userlib.DatastoreGet(entry.EntryKey)
	if ok == false {
		return nil, errors.New(strings.ToTitle("File doesn't exist"))
	}

	file, err := verifyAndDecrypt(entry.SymEncKey, entry.SymSignKey, fileEncrypted)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(metadata.Appends); i++ {
		appendEnc, ok := userlib.DatastoreGet(metadata.Appends[i])
		if ok == false {
			return nil, err
		}

		appendFile, err := verifyAndDecrypt(entry.SymEncKey, entry.SymSignKey, appendEnc)
		if err != nil {
			return nil, err
		}

		for i := 0; i < len(appendFile); i++ {
			file = append(file, appendFile[i])
		}
	}

	return file, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	// TODO: should we assume that "recipient" is a valid user
	// TODO: if the function fails in the middle, make sure we REVERT the changes to datastore
	// or delay the changes to datastore until we make some likely-to-fail calls

	metadata, err := userdata.getFileMetadata(filename)
	if err != nil {
		return "", err
	}

	entry, ok := metadata.SharingTree[userdata.Username]
	if ok == false {
		return "", errors.New(strings.ToTitle("Doesn't have access to this file"))
	}

	// the new user need to have these in their MapEntry
	fileEncKey, err := userlib.PKEDec(userdata.PrivateDec, entry.SymEncKey)
	if err != nil {
		return "", err
	}

	fileSignKey, err := userlib.PKEDec(userdata.PrivateDec, entry.SymSignKey)
	if err != nil {
		return "", err
	}

	// recipient's public encryption key
	recEncKey, ok := userlib.KeystoreGet(recipient + "_enc")
	if ok == false {
		return "", errors.New(strings.ToTitle("Public Key not found"))
	}

	var newEntry MapEntry
	newEntry.EntryKey = entry.EntryKey
	newEntry.SymEncKey, err = userlib.PKEEnc(recEncKey, fileEncKey)
	if err != nil {
		return "", err
	}

	newEntry.SymSignKey, err = userlib.PKEEnc(recEncKey, fileSignKey)
	if err != nil {
		return "", err
	}

	// RevokeFile will use this to check for direct children relationships
	entry.Children = append(entry.Children, recipient)

	// contains updated child array
	metadata.SharingTree[userdata.Username] = entry
	// contains the new entry for the recipient
	metadata.SharingTree[recipient] = newEntry

	metafileJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}

	// overriding the original metadata with updated metadata
	userlib.DatastoreSet(metadata.KeyToMetaData, metafileJSON)

	// the token is a SHA-512 hash, so we don't need to encrypt it any further
	var token Token
	token.MetaDataKey = metadata.KeyToMetaData
	// signature is provided to supporting checking the integrity
	token.Signature, err = userlib.DSSign(userdata.PrivateSign, metadata.KeyToMetaData[:])
	if err != nil {
		return "", err
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	// Create a random pointer to tokenJSON, allows for unique and one-time access tokens
	keyPtr, err := uuid.FromBytes(userlib.RandomBytes(16))
	userlib.DatastoreSet(keyPtr, tokenJSON)

	return string(keyPtr[:]), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	tokenJSONuuid, err := uuid.FromBytes([]byte(magic_string))
	if err != nil {
		return err
	}

	tokenJSON, ok := userlib.DatastoreGet(tokenJSONuuid)
	if ok == false {
		return errors.New(strings.ToTitle("Access token not valid"))
	}

	// deleting the access token
	userlib.DatastoreDelete(tokenJSONuuid)

	var token Token

	err = json.Unmarshal(tokenJSON, &token)
	if err != nil {
		return err
	}

	// recipient's public encryption key
	senderSignKey, ok := userlib.KeystoreGet(sender + "_sign")
	if ok == false {
		return errors.New(strings.ToTitle("Sender's signing key not found"))
	}

	// checking for integrity and authenticity
	err = userlib.DSVerify(senderSignKey, token.MetaDataKey[:], token.Signature)
	if err != nil {
		return errors.New(strings.ToTitle("Token was tampered with"))
	}

	pointerValue, err := json.Marshal(token.MetaDataKey)
	if err != nil {
		return err
	}

	pointerValue, err = encryptAndSign(userdata.encryptKey, userdata.signKey, pointerValue)
	if err != nil {
		return err
	}

	// the key in the datastore for storing the file
	var hashOfPtr = userlib.Hash([]byte("ptr/" + userdata.Username + "/" + filename))
	var pointerKey = bytesToUUID(hashOfPtr[:])

	// key = UUID("ptr/" + username + "/" + filename)
	// value = HMAC + SymEnc(UUID("meta/" + userdata.Username + "/" + filename))
	userlib.DatastoreSet(pointerKey, pointerValue)
	return nil
}

func (entry *MapEntry) isDirectChild(child string) bool {

	for i := 0; i < len(entry.Children); i++ {
		if entry.Children[i] == child {
			return true
		}
	}
	return false
}

func (meta *FileMetaData) removeRecursively(key string) error {

	entry, ok := meta.SharingTree[key]
	if ok == false {
		return errors.New(strings.ToTitle("Entry doesn't exist anymore"))
	}

	for i := 0; i < len(entry.Children); i++ {
		err := meta.removeRecursively(entry.Children[i])
		if err != nil {
			return err
		}
	}
	delete(meta.SharingTree, key)
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {

	meta, err := userdata.getFileMetadata(filename)

	// check for integrity of the owner whenever ShareFile is called
	hmac, err := userlib.HMACEval(userdata.signKey, []byte(meta.Owner))
	if err != nil {
		return err
	}

	// make sure the root owner is calling this function
	if userlib.HMACEqual(hmac, meta.OwnerHMAC) == false {
		return errors.New(strings.ToTitle("Only root owner can revoke accesses"))
	}

	root, ok := meta.SharingTree[userdata.Username]
	if ok == false {
		return errors.New(strings.ToTitle("Sharing Tree was tampered"))
	}

	if root.isDirectChild(target_username) {
		// remove from root entry's children array
		var newChildren []string
		for i := 0; i < len(root.Children); i++ {
			if root.Children[i] != target_username {
				newChildren = append(newChildren, root.Children[i])
			}
		}

		// recursively remove from entry and metadata
		meta.removeRecursively(target_username)

		metafileJSON, err := json.Marshal(meta)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(meta.KeyToMetaData, metafileJSON)
		return nil
	}
	return errors.New(strings.ToTitle("Not a direct child of root"))
}
