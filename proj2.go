package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
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

type FileKeys struct {
	MacKey []byte
	SymmetricKey []byte
	EndUUID uuid.UUID
	HeadUUID uuid.UUID
}

// The structure definition for a user record
type User struct {
	Username string
	RSADecryptionKey userlib.PKEDecKey
	HeadFile uuid.UUID
	MacKey []byte
	Signature userlib.DSSignKey
	Files map[string]FileKeys

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type File struct {
	Data []byte
}

type MetaData struct {
	FilePointer uuid.UUID
	Next uuid.UUID
	Current uuid.UUID
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
	var userdata User
	userdataptr = &userdata
	if username == "" || password == "" {
		return nil, errors.New("Initialization Error")
	}
	userdata.Username = username
	empty := make([]byte, 16)
	for i := 0; i < 16; i++ {
		empty[i] = uint8(0)
	}
	userdata.HeadFile, _ = uuid.FromBytes(empty)
	rsaEncypt, rsaDecrypt, error := userlib.PKEKeyGen()
	if error != nil {
		return nil, errors.New("RSA Error")
	}
	userlib.KeystoreSet(username + "_rsaek", rsaEncypt)
	userdata.RSADecryptionKey = rsaDecrypt

	dsSign, dsVerify, error := userlib.DSKeyGen()
	if error != nil {
		return nil, errors.New("DS Error")
	}
	userlib.KeystoreSet(username + "_ds", dsVerify)
	userdata.Signature = dsSign
	userdata.Files = make(map[string]FileKeys)
	masterKey := userlib.Argon2Key([]byte(password), []byte(username + "salt"), 16)
	macMasterKey := userlib.Argon2Key([]byte(password), []byte(username + "MAC"), 16)
	userdata.MacKey = macMasterKey
	hashedMasterKey := userlib.Hash([]byte(masterKey))
	jsonUser, error := json.Marshal(userdata)
	if error != nil {
		return nil, errors.New("Marshall Error")
	}
	iv := make([]byte, userlib.AESBlockSize)
	for i := 0; i < userlib.AESBlockSize; i++ {
		iv[i] = jsonUser[i]
	}
	padding := userlib.AESBlockSize - (len(jsonUser) % userlib.AESBlockSize)
	if padding == 0 {
		padding = 16
	}
	paddedArray := make([]byte, padding + len(jsonUser))
	for i := 0; i < len(paddedArray); i++ {
		if i < len(jsonUser) {
			paddedArray[i] = jsonUser[i]
		} else {
			paddedArray[i] = uint8(padding)
		}
	}
	encryptedData := userlib.SymEnc([]byte(masterKey), []byte(iv), []byte(paddedArray))
	dataMac, error := userlib.HMACEval([]byte(userdata.MacKey), []byte(encryptedData))
	if error != nil {
		return nil, errors.New("Init MAC Error")
	}
	passwordUUID, error := uuid.FromBytes(hashedMasterKey[:16])
	if error != nil {
		return nil, errors.New("Init UUID Error")
	}
	userlib.DatastoreSet(passwordUUID, append(encryptedData, dataMac...))
	return &userdata, nil
}

// Helper function that tests if the attached MAC is valid or not and returns the encrypted portion of the JSON
func testMacValid(data []byte, username string, macKey []byte) (encrypted []byte, err error) {
	if len(data) < userlib.HashSize {
		return nil, errors.New("Empty data")
	}
	hmac := make([]byte, userlib.HashSize)
	encrypted = make([]byte, len(data) - userlib.HashSize)
	counter := 0
	for i := len(data) - userlib.HashSize; i < len(data); i++ {
		hmac[counter] = data[i]
		counter++
	}
	for i := 0; i < len(data) - userlib.HashSize; i++ {
		encrypted[i] = data[i]
	}
	dataMac, typeError := userlib.HMACEval([]byte(macKey), []byte(encrypted))
	if typeError != nil {
		return nil, errors.New("Get MAC Error")
	}
	for i := 0; i < userlib.HashSize; i++ {
		if dataMac[i] != hmac[i] {
			return nil, errors.New("Tampered Data")
		}
	}
	return encrypted, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	_, error := userlib.KeystoreGet(username + "_rsaek")
	if !error {
		return nil, errors.New("Not a user")
	}
	masterKey := userlib.Argon2Key([]byte(password), []byte(username + "salt"), 16)
	hashedMasterKey := userlib.Hash([]byte(masterKey))
	passwordUUID, typeError := uuid.FromBytes(hashedMasterKey[:16])
	if typeError != nil {
		return nil, errors.New("Get UUID error")
	}
	data, error := userlib.DatastoreGet(passwordUUID)
	if !error {
		return nil, errors.New("Incorrect Password")
	}
	macMasterKey := userlib.Argon2Key([]byte(password), []byte(username + "MAC"), 16)
	encrypted, macerr := testMacValid(data, username, macMasterKey)
	if macerr != nil {
		return nil, macerr
	}
	decrypted := userlib.SymDec([]byte(masterKey), encrypted)
	var userdata User

	unpadded := make([]byte, len(decrypted) - int(decrypted[len(decrypted) - 1]))
	for i := 0; i < len(decrypted) - int(decrypted[len(decrypted) - 1]); i++ {
		unpadded[i] = decrypted[i]
	}
	typeError = json.Unmarshal(unpadded, &userdata)
	if typeError != nil {
		return nil, errors.New("Unmarshal Error")
	}
	userdataptr = &userdata
	return userdataptr, nil
}

func checkInitialUUID(testing uuid.UUID) int {
	for i := 0; i < 16; i++ {
		if testing[i] != 0 {
			return 1;
		}
	}
	return 0;
}

func storeIntoDatastore(masterKey []byte, macKey []byte, jsonFile []byte, UUID uuid.UUID) {
	iv := make([]byte, userlib.AESBlockSize)
	for i := 0; i < userlib.AESBlockSize; i++ {
		iv[i] = jsonFile[i]
	}
	padding := userlib.AESBlockSize - (len(jsonFile) % userlib.AESBlockSize)
	if padding == 0 {
		padding = 16
	}
	paddedArray := make([]byte, padding + len(jsonFile))
	for i := 0; i < len(paddedArray); i++ {
		if i < len(jsonFile) {
			paddedArray[i] = jsonFile[i]
		} else {
			paddedArray[i] = uint8(padding)
		}
	}
	encryptedData := userlib.SymEnc([]byte(masterKey), []byte(iv), []byte(paddedArray))
	dataMac, _ := userlib.HMACEval([]byte(macKey), []byte(encryptedData))
	userlib.DatastoreSet(UUID, append(encryptedData, dataMac...))
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	//_, exist := userlib.DatastoreGet(UUID)
	var newFile File
	/*if exist {
		currentFile, _ := userlib.DatastoreGet(UUID)
		encrypted, _ := testMacValid(currentFile, userdata.Username, userdata.MacKey)
		decryptedFile, _ := userlib.PKEDec(userdata.RSADecryptionKey, []byte(encrypted))
		_ = json.Unmarshal(decryptedFile, &newFile)
	} else {
		userdata.HeadFile = UUID
	}*/
	newFile.Data = data
	jsonFile, _ := json.Marshal(newFile)
	randomBytes := userlib.RandomBytes(16)
	masterKey := userlib.Argon2Key(randomBytes, []byte(userdata.Username + "salt"), 16)
	macKey := userlib.Argon2Key(randomBytes, []byte(userdata.Username + "macsalt"), 16)
	storeIntoDatastore(masterKey, macKey, jsonFile, UUID)

	var tempKeys FileKeys
	tempKeys.MacKey = macKey
	tempKeys.SymmetricKey = masterKey
	tempKeys.EndUUID = uuid.New()
	tempKeys.HeadUUID = tempKeys.EndUUID
	userdata.Files[filename] = tempKeys

	var headNode MetaData
	headNode.FilePointer = UUID
	headNode.Next = uuid.New()
	headNode.Current = tempKeys.HeadUUID
	jsonFile, _ = json.Marshal(headNode)
	storeIntoDatastore(masterKey, macKey, jsonFile, tempKeys.HeadUUID)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	_, exist := userlib.DatastoreGet(UUID)
	if !exist {
		return errors.New("Append File does not exist")
	}
	node, exist := userlib.DatastoreGet(userdata.Files[filename].EndUUID)
	if !exist {
		return errors.New("End file does not exist")
	}
	encrypted, macerr := testMacValid(node, userdata.Username, userdata.Files[filename].MacKey)
	if macerr != nil {
		return macerr
	}
	var current MetaData
	decryptedFile := userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
	unpadded := unpad(decryptedFile)
	ume := json.Unmarshal(unpadded, &current)
	if ume != nil {
		return errors.New("Unmarshal error")
	}
	appendedUUID := uuid.New()
	newNodeUUID := uuid.New()
	current.Next = newNodeUUID

	var newFile File
	newFile.Data = data
	jsonFile, _ := json.Marshal(newFile)
	storeIntoDatastore(userdata.Files[filename].SymmetricKey, userdata.Files[filename].MacKey, jsonFile, appendedUUID)

	var newNode MetaData
	newNode.FilePointer = appendedUUID
	newNode.Next = uuid.New()
	newNode.Current = newNodeUUID
	jsonFile, _ = json.Marshal(newNode)
	storeIntoDatastore(userdata.Files[filename].SymmetricKey, userdata.Files[filename].MacKey, jsonFile, newNodeUUID)
	jsonFile, _ = json.Marshal(current)
	storeIntoDatastore(userdata.Files[filename].SymmetricKey, userdata.Files[filename].MacKey, jsonFile, current.Current)

	var updatedKeys FileKeys
	updatedKeys.MacKey = userdata.Files[filename].MacKey
	updatedKeys.SymmetricKey = userdata.Files[filename].SymmetricKey
	updatedKeys.EndUUID = newNodeUUID
	updatedKeys.HeadUUID = userdata.Files[filename].HeadUUID
	userdata.Files[filename] = updatedKeys
	return
}

func unpad(data []byte) (ans []byte) {
	unpadded := make([]byte, len(data) - int(data[len(data) - 1]))
	for i := 0; i < len(data) - int(data[len(data) - 1]); i++ {
		unpadded[i] = data[i]
	}
	return unpadded
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	answer := make([]byte, 0)
	node, exist := userlib.DatastoreGet(userdata.Files[filename].HeadUUID)
	if !exist {
		return nil, errors.New("Load File does not exist")
	}
	for {
		encrypted, macerr := testMacValid(node, userdata.Username, userdata.Files[filename].MacKey)
		if macerr != nil {
			return nil, macerr
		}
		var current MetaData
		decryptedFile := userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
		unpadded := unpad(decryptedFile)
		ume := json.Unmarshal(unpadded, &current)
		if ume != nil {
			return nil, errors.New("Unmarshal error")
		}
		file, exist := userlib.DatastoreGet(current.FilePointer)
		if !exist {
			return nil, errors.New("Load File does not exist")
		}
		var currentFile File
		encrypted, macerr = testMacValid(file, userdata.Username, userdata.Files[filename].MacKey)
		if macerr != nil {
			return nil, macerr
		}
		decryptedFile = userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
		unpadded = unpad(decryptedFile)
		ume = json.Unmarshal(unpadded, &currentFile)
		if ume != nil {
			return nil, errors.New("Unmarshal error")
		}
		answer = append(answer, currentFile.Data...)
		if current.Current == userdata.Files[filename].EndUUID {
			break
		}
		node, exist = userlib.DatastoreGet(current.Next)
		if !exist {
			return nil, errors.New("Tampering in file structure")
		}
	}
	return answer, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	recKey, error := userlib.KeystoreGet(recipient + "_rsaek")
	if !error {
		return "", errors.New("Receipient not a user")
	}
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	_, exist := userlib.DatastoreGet(UUID)
	if !exist {
		return "", errors.New("Share File does not exist")
	}
	var headFile File
	//headFile.Appended = UUID
	jsonHeadFile, jsonError := json.Marshal(headFile)
	if jsonError != nil {
		return "", errors.New("Marshal error")
	}

	encrypted, encError := userlib.PKEEnc(recKey, []byte(jsonHeadFile))
	if encError != nil {
		return "", errors.New("Encryption error")
	}
	signature, encError := userlib.DSSign(userdata.Signature, encrypted)
	if encError != nil {
		return "", errors.New("Signature error")
	}
	accessPoint := uuid.New()
	ans := append(encrypted, signature...)
	userlib.DatastoreSet(accessPoint, ans)
	return string(ans), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	_, exist := userlib.DatastoreGet(UUID)
	if exist {
		return errors.New("Cannot use existing file name")
	}
	verifyKey, verKeyError := userlib.KeystoreGet(sender + "_ds")
	if !verKeyError {
		return errors.New("Verify key error")
	}
	if len(magic_string) < 256 {
		return errors.New("Empty string")
	}
	signature := make([]byte, 256)
	encrypted := make([]byte, len(magic_string) - 256)
	counter := 0
	for i := len(magic_string) - 256; i < len(magic_string); i++ {
		signature[counter] = magic_string[i]
		counter++
	}
	for i := 0; i < len(magic_string) - 256; i++ {
		encrypted[i] = magic_string[i]
	}
	tampering := userlib.DSVerify(verifyKey, encrypted, signature)
	if tampering != nil {
		return errors.New("Magic String tampered")
	}
	decrypted, decError := userlib.PKEDec(userdata.RSADecryptionKey, encrypted)
	if decError != nil {
		return errors.New("Receive Decryption error")
	}
	var newFile File
	umarshError := json.Unmarshal(decrypted, &newFile)
	if umarshError != nil {
		return errors.New("Unmarshal error")
	}
	jsonFile, _ := json.Marshal(newFile)
	encryptionKey, _ := userlib.KeystoreGet(userdata.Username + "_rsaek")
	encryptedFile, _ := userlib.PKEEnc(encryptionKey, []byte(jsonFile))
	fileMac, _ := userlib.HMACEval([]byte(userdata.MacKey), []byte(encryptedFile))
	userlib.DatastoreSet(UUID, append(encryptedFile, fileMac...))
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
