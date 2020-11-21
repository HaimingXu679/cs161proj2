package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	"github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.

	// Test: retrieving a valid user
	_, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	// Test: trying to retrieve an invalid user
	_, err = GetUser("bob", "fubar")
	if err == nil {
		t.Error("Failed to detect invalid user", err)
		return
	}

	// Test: wrong password for valid user
	_, err = GetUser("alice", "f")
	if err == nil {
		t.Error("Failed to detect wrong password", err)
		return
	}

	// Test: correct retrieval
	data, _ := GetUser("alice", "fubar")
	if data.Username != "alice" {
		t.Error("Failed to get correct data", err)
		return
	}

	// Test: identify json tampering
	masterKey := userlib.Argon2Key([]byte("fubar"), []byte("alice" + "salt"), 16)
	hashedMasterKey := userlib.Hash([]byte(masterKey))
	passwordUUID, _ := uuid.FromBytes(hashedMasterKey[:16])
	temp, _ := userlib.DatastoreGet(passwordUUID)
	garbage := make([]byte, len(temp))
	userlib.DatastoreSet(passwordUUID, garbage)
	_, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("Failed to detect tampering", err)
		return
	}

	t.Log("All passed")
}

func TestTwoInit(t *testing.T) {
	clear()
	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err = InitUser("alice", "fubar")
	if err == nil {
		t.Error("Failed to detect existing user", err)
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("First Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	// Test: two users with same file name should not overwrite
	u2, err := InitUser("bob", "adsf")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v3 := []byte("Bob's file")
	u2.StoreFile("file1", v3)
	v2, err2 = u.LoadFile("file1")
	if err2 != nil {
		t.Error("Second Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Bob file overwrote Alice's", v, v2)
		return
	}

	// Test: user overwrite their own file
	v4 := []byte("This is a not a test")
	u.StoreFile("file1", v4)
	loaded, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Thid Failed to upload and download", err2)
		return
	}
	if reflect.DeepEqual(v, loaded) {
		t.Error("File not overwritten")
		return
	}
	if !reflect.DeepEqual(v4, loaded) {
		t.Error("File overwrite error")
		return
	}

	// Test: check if the file is secure

}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("This is a test ")
	u.StoreFile("file1", v)
	u.AppendFile("file1", v)
	u.AppendFile("file1", v)
	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if string(v2) != "This is a test " + "This is a test " + "This is a test " {
		t.Error("Append error")
	}
	u.StoreFile("file1", v)
	u.AppendFile("file1", v)
	v2, err2 = u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if string(v2) != "This is a test " + "This is a test " {
		t.Error("Append error")
		userlib.DebugMsg("%s", v2)
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v = []byte("This is not a test ")
	u2.StoreFile("file1", v)
	u2.AppendFile("file1", v)
	msg2 := []byte("Different 1 ")
	msg3 := []byte("Different 2")
	u2.AppendFile("file1", msg2)
	u2.AppendFile("file1", msg3)
	v2, err2 = u2.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if string(v2) != "This is not a test " + "This is not a test " + "Different 1 " + "Different 2" {
		t.Error("Append error")
		userlib.DebugMsg("%s", v2)
	}
	return
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	append := []byte("Adding stuff")
	u2.AppendFile("file2", append)
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestRevoke1(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err2 := InitUser("joe", "joemama")
	if err2 != nil {
		t.Error("Failed to initialize joe", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "joe")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}

	revokeErr := u.RevokeFile("file1", "bob")
	if revokeErr != nil {
		t.Error("Revoke error", err)
		return
	}
	appendMsg := []byte("Hello hello hello")
	u2.AppendFile("file2", appendMsg)
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Revoked file is the same", v, v2)
		return
	}
}

func TestRevoke2(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err2 := InitUser("joe", "joemama")
	if err2 != nil {
		t.Error("Failed to initialize joe", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	var v2 []byte
	var magic_string string
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	magic_string, err = u.ShareFile("file1", "joe")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	err = u.RevokeFile("file1", "joe")
	if err != nil {
		t.Error(err)
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Non-revoked child lost access", v, v2)
		return
	}
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error(err)
	}
	empty := []byte("")
	append := []byte("Garbage")
	u2.AppendFile("file2", append)
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(append, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Appended to revoked file", v, v2)
		return
	}
	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(empty, v2) {
		userlib.DebugMsg("First: %s", empty)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Still retained access", v, v2)
		return
	}
}

func TestRevoke3(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err2 := InitUser("joe", "joemama")
	if err2 != nil {
		t.Error("Failed to initialize joe", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	var v2 []byte
	var magic_string string
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	magic_string, err = u.ShareFile("file1", "joe")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	append := []byte("Appending stuff here")
	u.AppendFile("file1", append)
	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after appending", err)
		return
	}
	v3, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after owner appended", err)
		return
	}
	if !reflect.DeepEqual(v2, v3) {
		userlib.DebugMsg("First: %s", v2)
		userlib.DebugMsg("Second: %s", v3)
		t.Error("Shared file is not the same", v2, v3)
		return
	}
}

// Share chain
func TestShareChain(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err2 := InitUser("joe", "joemama")
	if err2 != nil {
		t.Error("Failed to initialize joe", err2)
		return
	}
	v := []byte("Hello hello hello")
	u.StoreFile("file1", v)
	var magic_string string
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	magic_string, err = u2.ShareFile("file2", "joe")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

// Share chain with append
func TestShareChainWithAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err2 := InitUser("joe", "joemama")
	if err2 != nil {
		t.Error("Failed to initialize joe", err2)
		return
	}
	v := []byte("Hello hello hello")
	u.StoreFile("file1", v)
	var magic_string string
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	magic_string, err = u2.ShareFile("file2", "joe")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}

	appendData := []byte("AppendedData")
	appendError := u.AppendFile("file1", appendData)
	if appendError != nil {
		t.Error("Append error", appendError)
		return
	}
	realData, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after appending", err)
		return
	}
	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	appendData = []byte("AppendedData2")
	appendError = u2.AppendFile("file2", appendData)
	if appendError != nil {
		t.Error("Append error", appendError)
		return
	}
	realData, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after appending", err)
		return
	}
	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

// Revoke chain propogates
func TestRevokeChainPropogation(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err2 := InitUser("joe", "joemama")
	if err2 != nil {
		t.Error("Failed to initialize joe", err2)
		return
	}
	v := []byte("Hello hello hello")
	u.StoreFile("file1", v)
	var magic_string string
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	magic_string, err = u2.ShareFile("file2", "joe")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
	revokeError := u.RevokeFile("file1", "bob")
	if revokeError != nil {
		t.Error("Revoke error", revokeError)
		return
	}
	empty := []byte("")
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(empty, v2) {
		userlib.DebugMsg("First: %s", empty)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Still retained access", v, v2)
		return
	}
	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(empty, v2) {
		userlib.DebugMsg("First: %s", empty)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Still retained access", v, v2)
		return
	}
}

// Share file that doesn't exist
func TestNonexistantFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	_, error := u.ShareFile("file1", "bob")
	if error == nil {
		t.Error("Failed to check for non-existant file")
		return
	}
}

// Append first then share
func TestAppendFirstThenShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	appended := []byte("APpended stuff")
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	_ = u.AppendFile("file1", appended)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	realData, _ := u.LoadFile("file1")
	v2, _ := u2.LoadFile("file2")
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", realData, v2)
		return
	}
}

// Retrieve file sender doesn't exist
func TestRetrieveFileNonexistantSender(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = u2.ReceiveFile("file2", "jay", magic_string)
	if err == nil {
		t.Error("Failed to detect non-existant sender", err)
		return
	}
}

// Retrieve file sender doesn't exist
func TestAdversaryReceivesToken(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	av, err2 := InitUser("mean", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize mean", err2)
		return
	}
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = av.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("Failed to detect adversary", err)
		return
	}
}

// Share file with non-existant user
func TestShareFileWithNonexistantUser(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err = u.ShareFile("file1", "jay")
	if err == nil {
		t.Error("Failed to detect non-existant recipient", err)
		return
	}
}

// Security test: tampered MAC for magic word
func TestTamperedMagicString(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	appended := []byte("APpended stuff")
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	_ = u.AppendFile("file1", appended)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	magic_string = ""
	for i := 0; i < 512; i++ {
		magic_string += "Q"
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("Failed to detect tampering", err)
		return
	}
}

// Revoke from non-shared recipient
func TestRevokeFromNonShared(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	appended := []byte("APpended stuff")
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	_ = u.AppendFile("file1", appended)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	realData, _ := u.LoadFile("file1")
	v2, _ := u2.LoadFile("file2")
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", realData, v2)
		return
	}
	revokeError := u.RevokeFile("file1", "jay")
	if revokeError == nil {
		t.Error("Revoked from non-shared user")
		return
	}
}

// Revoke access then give access again
func TestRevokeThenShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	appended := []byte("APpended stuff")
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	_ = u.AppendFile("file1", appended)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	realData, _ := u.LoadFile("file1")
	v2, _ := u2.LoadFile("file2")
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", realData, v2)
		return
	}
	revokeError := u.RevokeFile("file1", "bob")
	if revokeError != nil {
		t.Error("Revoke error", revokeError)
		return
	}
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	// BOB MUST USE DIFFERENT NAME THAN BEFORE?
	err = u2.ReceiveFile("file3", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	realData, _ = u.LoadFile("file1")
	v2, _ = u2.LoadFile("file3")
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", realData, v2)
		return
	}
}

// Share file and recipient overwrites
func TestRecipientOverwrite(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	appended := []byte("APpended stuff")
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	_ = u.AppendFile("file1", appended)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	realData, _ := u.LoadFile("file1")
	v2, _ := u2.LoadFile("file2")
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", realData, v2)
		return
	}
	overwrite := []byte("This file has been overwritten")
	u2.StoreFile("file2", overwrite)
	realData, _ = u2.LoadFile("file2")
	v2, _ = u.LoadFile("file1")
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file that was overwritten is not the same", realData, v2)
		return
	}
}

// Share file and owner overwrites
func TestOwnerOverwrite(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	appended := []byte("APpended stuff")
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	_ = u.AppendFile("file1", appended)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	realData, _ := u.LoadFile("file1")
	v2, _ := u2.LoadFile("file2")
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", realData, v2)
		return
	}
	overwrite := []byte("This file has been overwritten")
	u.StoreFile("file1", overwrite)
	realData, _ = u.LoadFile("file1")
	v2, _ = u2.LoadFile("file2")
	if !reflect.DeepEqual(realData, v2) {
		userlib.DebugMsg("First: %s", realData)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file that was overwritten is not the same", realData, v2)
		return
	}
}

// Bob receives file1 even though he already has file 1
func TestReceiveExistingFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	appended := []byte("APpended stuff")
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	u2.StoreFile("file2", v)
	_ = u.AppendFile("file1", appended)
	magic_string, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("Failed to detect existing file", err)
		return
	}
}

// u1 is alice AND u2 is Alice
func TestTwoInstancesOfAlice(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user 1", err)
		return
	}
	u, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user 2", err)
		return
	}
	u2, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		t.Error("Failed to get alice", err2)
		return
	}
	v := []byte("Random stuff")
	u.StoreFile("file1", v)
	v2, err := u.LoadFile("file1")
	if err != nil {
		t.Error("U1 Failed to detect multiple instance of user with same file", err)
		return
	}
	v2, err = u2.LoadFile("file1")
	if err != nil {
		t.Error("U2 Failed to detect multiple instance of user with same file", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		userlib.DebugMsg("First: %s", v)
		userlib.DebugMsg("Second: %s", v2)
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestReceiveFromSelf(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err := InitUser("bob", "alice")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	u2.StoreFile("file1", v)
	magic_string, err := u.ShareFile("file1", "bob")
	err = u.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("Failed to detect send to self", err)
		return
	}
	err = u.ReceiveFile("file1", "alice", magic_string)
	if err == nil {
		t.Error("Failed to detect send to self", err)
		return
	}
	err = u2.ReceiveFile("file1", "alice", magic_string)
	if err == nil {
		t.Error("Failed to existing file when sharing", err)
		return
	}
}

func TestShareWithSelf(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("Garbage stuff")
	u.StoreFile("file1", v)
	_, err 	= u.ShareFile("file1", "alice")
	if err == nil {
		t.Error("Failed to detect share to self", err)
		return
	}
}
