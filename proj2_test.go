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
		t.Error("Failed to upload and download", err2)
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
		t.Error("Failed to upload and download", err2)
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
		t.Error("Failed to upload and download", err2)
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
		t.Error("Shared file is not the same", v, v2)
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
	}
	return
}
