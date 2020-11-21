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
	HeadUUID uuid.UUID
}

// The structure definition for a user record
type User struct {
	Username string
	RSADecryptionKey userlib.PKEDecKey
	MacKey []byte
	Signature userlib.DSSignKey
	Files map[string]FileKeys
	SharedWithOthers map[string]map[string]uuid.UUID
	Password string
}

type File struct {
	Data []byte
}

type MetaData struct {
	FilePointer uuid.UUID
	Next uuid.UUID
	Current uuid.UUID
	EndUUID uuid.UUID
}

type Magic struct {
	Head uuid.UUID
	SymmetricKey []byte
	MacKey []byte
}

func unpad(data []byte) (ans []byte) {
	unpadded := make([]byte, len(data) - int(data[len(data) - 1]))
	for i := 0; i < len(data) - int(data[len(data) - 1]); i++ {
		unpadded[i] = data[i]
	}
	return unpadded
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
	iv := userlib.RandomBytes(userlib.AESBlockSize)
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

func testMacValid(data []byte, macKey []byte) (encrypted []byte, err error) {
	if len(data) < userlib.HashSize {
		return nil, errors.New("Empty data")
	}

	// Band-aid fix
	if len(macKey) != 16 {
		return nil, errors.New("Tampered key")
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

func getUpdatedUser(userdata *User) (returndata *User) {
	map1 := userdata.Files
	map2 := userdata.SharedWithOthers
	temp, _ := GetUser(userdata.Username, userdata.Password)
	for k, v := range temp.Files {
    map1[k] = v
	}
	for k, v := range temp.SharedWithOthers {
		for a, b := range v {
    	map2[k][a] = b
		}
	}
	userdata.Files = map1
	userdata.SharedWithOthers = map2
	return userdata
}

func updateUser(userdata *User) {
	jsonFile, _ := json.Marshal(userdata)
	masterKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username + "salt"), 16)
	hashedMasterKey := userlib.Hash([]byte(masterKey))
	passwordUUID, _ := uuid.FromBytes(hashedMasterKey[:16])
	storeIntoDatastore(masterKey, userdata.MacKey, jsonFile, passwordUUID)
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
	_, startError := userlib.KeystoreGet(username + "_rsaek")
	if startError {
		return nil, errors.New("Already a user")
	}
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
	userdata.Password = password
	userdata.Files = make(map[string]FileKeys)
	userdata.SharedWithOthers = make(map[string]map[string]uuid.UUID)
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
	encrypted, macerr := testMacValid(data, macMasterKey)
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

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	userdata = getUpdatedUser(userdata)
	//UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	UUID := uuid.New()
	flag := 0
	var current MetaData
	if _, ok := userdata.Files[filename]; ok {
		flag = 1
		traverse := userdata.Files[filename].HeadUUID
		for {
			node, _ := userlib.DatastoreGet(traverse)
			encrypted, _ := testMacValid(node, userdata.Files[filename].MacKey)
			decryptedFile := userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
			unpadded := unpad(decryptedFile)
			_ = json.Unmarshal(unpadded, &current)
			file, _ := userlib.DatastoreGet(current.FilePointer)
			testFile, _ := testMacValid(file, userdata.Files[filename].MacKey)
			var associatedFile File
			decryptedFile = userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(testFile))
			unpadded = unpad(decryptedFile)
			_ = json.Unmarshal(unpadded, &associatedFile)
			if len(associatedFile.Data) != 0 {
				UUID = current.FilePointer
				break
			}
			traverse = current.Next
		}
	}
	var newFile File
	newFile.Data = data
	jsonFile, _ := json.Marshal(newFile)
	randomBytes := userlib.RandomBytes(16)
	masterKey := userlib.Argon2Key(randomBytes, []byte(userdata.Username + "salt"), 16)
	macKey := userlib.Argon2Key(randomBytes, []byte(userdata.Username + "macsalt"), 16)
	if flag == 1 {
		masterKey = userdata.Files[filename].SymmetricKey
		macKey = userdata.Files[filename].MacKey
	}
	storeIntoDatastore(masterKey, macKey, jsonFile, UUID)
	var tempKeys FileKeys
	if flag == 0 {
		tempKeys.MacKey = macKey
		tempKeys.SymmetricKey = masterKey
		tempKeys.HeadUUID = uuid.New()
		userdata.Files[filename] = tempKeys
	}
	current.Next = uuid.New()
	if flag == 0 {
		current.FilePointer = UUID
		current.Current = tempKeys.HeadUUID
		current.EndUUID = tempKeys.HeadUUID
	}
	jsonFile, _ = json.Marshal(current)
	if flag == 0 {
		storeIntoDatastore(masterKey, macKey, jsonFile, tempKeys.HeadUUID)
	} else {
		storeIntoDatastore(masterKey, macKey, jsonFile, current.Current)
	}
	updateUser(userdata)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	userdata = getUpdatedUser(userdata)
	if _, ok := userdata.Files[filename]; !ok {
		return errors.New("File to append to does not exist")
	}
	node, exist := userlib.DatastoreGet(userdata.Files[filename].HeadUUID)
	if !exist {
		return errors.New("Head metadata file does not exist")
	}
	encrypted, macerr := testMacValid(node, userdata.Files[filename].MacKey)
	if macerr != nil {
		return macerr
	}

	var headNode MetaData
	decryptedFile := userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
	unpadded := unpad(decryptedFile)
	ume := json.Unmarshal(unpadded, &headNode)
	if ume != nil {
		return errors.New("Unmarshal error")
	}
	node, exist = userlib.DatastoreGet(headNode.EndUUID)

	var current MetaData
	if !exist {
		return errors.New("End Metadata file does not exist")
	}
	encrypted, macerr = testMacValid(node, userdata.Files[filename].MacKey)
	if macerr != nil {
		return macerr
	}
	decryptedFile = userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
	unpadded = unpad(decryptedFile)
	ume = json.Unmarshal(unpadded, &current)
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
	updatedKeys.HeadUUID = userdata.Files[filename].HeadUUID
	userdata.Files[filename] = updatedKeys

	node, _ = userlib.DatastoreGet(userdata.Files[filename].HeadUUID)
	encrypted, _ = testMacValid(node, userdata.Files[filename].MacKey)
	decryptedFile = userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
	unpadded = unpad(decryptedFile)
	_ = json.Unmarshal(unpadded, &headNode)
	headNode.EndUUID = newNodeUUID
	_, exist = userlib.DatastoreGet(headNode.Next)
	if !exist {
		headNode.Next = newNodeUUID
	}
	jsonFile, _ = json.Marshal(headNode)
	storeIntoDatastore(userdata.Files[filename].SymmetricKey, userdata.Files[filename].MacKey, jsonFile, headNode.Current)

	node, _ = userlib.DatastoreGet(headNode.Next)
	encrypted, _ = testMacValid(node, userdata.Files[filename].MacKey)
	decryptedFile = userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
	unpadded = unpad(decryptedFile)
	_ = json.Unmarshal(unpadded, &headNode)
	headNode.EndUUID = newNodeUUID
	_, exist = userlib.DatastoreGet(headNode.Next)
	if !exist {
		headNode.Next = newNodeUUID
	}
	jsonFile, _ = json.Marshal(headNode)
	storeIntoDatastore(userdata.Files[filename].SymmetricKey, userdata.Files[filename].MacKey, jsonFile, headNode.Current)
	updateUser(userdata)
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	userdata = getUpdatedUser(userdata)
	answer := make([]byte, 0)
	node, exist := userlib.DatastoreGet(userdata.Files[filename].HeadUUID)
	if !exist {
		return nil, errors.New("Load File in beginning does not exist")
	}
	flag := 0
	terminate := uuid.New()
	for {
		encrypted, macerr := testMacValid(node, userdata.Files[filename].MacKey)
		if macerr != nil {
			return nil, macerr
		}
		var current MetaData
		decryptedFile := userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(encrypted))
		unpadded := unpad(decryptedFile)
		ume := json.Unmarshal(unpadded, &current)
		if flag == 0 {
			node, exist = userlib.DatastoreGet(current.FilePointer)
			if !exist {
				return nil, errors.New("File pointer does not exist")
			}
			testFile, macerr := testMacValid(node, userdata.Files[filename].MacKey)
			if macerr != nil {
				return nil, macerr
			}
			var associatedFile File
			decryptedFile := userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(testFile))
			unpadded := unpad(decryptedFile)
			_ = json.Unmarshal(unpadded, &associatedFile)
			node, exist = userlib.DatastoreGet(current.Next)
			if len(associatedFile.Data) > 0 || !exist {
				flag = 1
				terminate = current.EndUUID
			}
		}
		if ume != nil {
			return nil, errors.New("Unmarshal error")
		}
		file, exist := userlib.DatastoreGet(current.FilePointer)
		if !exist {
			return nil, errors.New("Load File in loop does not exist")
		}
		var currentFile File
		encrypted, macerr = testMacValid(file, userdata.Files[filename].MacKey)
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
		if current.Current == terminate {
			break
		}
		node, exist = userlib.DatastoreGet(current.Next)
		if !exist {
			return nil, errors.New("Tampering in file structure")
		}
	}
	updateUser(userdata)
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
	if userdata.Username == recipient {
		return "", errors.New("Can't share with self")
	}
	userdata = getUpdatedUser(userdata)
	_, exist := userlib.DatastoreGet(userdata.Files[filename].HeadUUID)
	if !exist {
		return "", errors.New("Load File in beginning does not exist")
	}

	n, ex := userlib.DatastoreGet(userdata.Files[filename].HeadUUID)
	if !ex {
		return "", errors.New("Head metadata file does not exist")
	}
	enc, macerr := testMacValid(n, userdata.Files[filename].MacKey)
	if macerr != nil {
		return "", macerr
	}
	var headNode MetaData
	dec := userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(enc))
	unpadded := unpad(dec)
	ume := json.Unmarshal(unpadded, &headNode)
	if ume != nil {
		return "", errors.New("Unmarshal error")
	}

	var newNode MetaData
	newNode.Next = userdata.Files[filename].HeadUUID
	newNode.FilePointer = uuid.New()
	newNode.Current = uuid.New()
	newNode.EndUUID = headNode.EndUUID


	jsonFile, jsonError := json.Marshal(newNode)
	if jsonError != nil {
		return "", errors.New("Marshal error")
	}
	storeIntoDatastore(userdata.Files[filename].SymmetricKey, userdata.Files[filename].MacKey, jsonFile, newNode.Current)

	var emptyFile File
	jsonFile, jsonError = json.Marshal(emptyFile)
	if jsonError != nil {
		return "", errors.New("Marshal error")
	}
	storeIntoDatastore(userdata.Files[filename].SymmetricKey, userdata.Files[filename].MacKey, jsonFile, newNode.FilePointer)
	_, exist = userlib.DatastoreGet(newNode.FilePointer)
	if !exist {
		return "", errors.New("asdfasdfasdfadsfasdf")
	}

	var ans Magic
	ans.SymmetricKey = userdata.Files[filename].SymmetricKey
	ans.Head = newNode.Current
	ans.MacKey = userdata.Files[filename].MacKey
	jsonAns, jsonError := json.Marshal(ans)
	if jsonError != nil {
		return "", errors.New("Marshal error")
	}
	encrypted, encError := userlib.PKEEnc(recKey, []byte(jsonAns))
	if encError != nil {
		return "", errors.New("Encryption error")
	}
	signature, encError := userlib.DSSign(userdata.Signature, encrypted)
	if encError != nil {
		return "", errors.New("Signature error")
	}
	finalans := append(encrypted, signature...)
	if _, ok := userdata.SharedWithOthers[filename]; !ok {
		userdata.SharedWithOthers[filename] = make(map[string]uuid.UUID)
	}
	mapCopy := userdata.SharedWithOthers[filename]
	mapCopy[recipient] = newNode.Current
	userdata.SharedWithOthers[filename] = mapCopy
	updateUser(userdata)
	return string(finalans), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	_, error := userlib.KeystoreGet(sender + "_rsaek")
	if !error {
		return errors.New("Sender not a user")
	}
	if sender == userdata.Username {
		return errors.New("Can't send to self")
	}
	userdata = getUpdatedUser(userdata)
	if _, ok := userdata.Files[filename]; ok {
		return errors.New("Can't use existing file name")
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
	var mag Magic
	umarshError := json.Unmarshal(decrypted, &mag)
	if umarshError != nil {
		return errors.New("Unmarshal error")
	}

	var fk FileKeys
	fk.MacKey = mag.MacKey
	fk.SymmetricKey = mag.SymmetricKey
	fk.HeadUUID = mag.Head
	userdata.Files[filename] = fk
	updateUser(userdata)
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	userdata = getUpdatedUser(userdata)
	if _, ok := userdata.SharedWithOthers[filename]; !ok {
		return errors.New("File does not exist")
	}
	if _, ok := userdata.SharedWithOthers[filename][target_username]; !ok {
		return errors.New("File is not shared with user in the first place")
	}
	n, ex := userlib.DatastoreGet(userdata.SharedWithOthers[filename][target_username])
	if !ex {
		return errors.New("Shared metadata file does not exist")
	}
	enc, macerr := testMacValid(n, userdata.Files[filename].MacKey)
	if macerr != nil {
		return macerr
	}
	var sharedNode MetaData
	dec := userlib.SymDec(userdata.Files[filename].SymmetricKey, []byte(enc))
	unpadded := unpad(dec)
	ume := json.Unmarshal(unpadded, &sharedNode)
	if ume != nil {
		return errors.New("Unmarshal error")
	}
	sharedNode.Next = uuid.New()
	sharedNode.EndUUID = sharedNode.Current
	jsonFile, jsonError := json.Marshal(sharedNode)
	if jsonError != nil {
		return errors.New("Marshal error")
	}
	storeIntoDatastore(userdata.Files[filename].SymmetricKey, userdata.Files[filename].MacKey, jsonFile, sharedNode.Current)
	delete(userdata.SharedWithOthers[filename], target_username)
	updateUser(userdata)
	return nil
}
