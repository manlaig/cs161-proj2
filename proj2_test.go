package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
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

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	_, error := GetUser("alice", "fubar")
	if error != nil {
		// t.Error says the test fails
		t.Error("Failed to get user", error)
		return
	}
}

func TestExistingUsername(t *testing.T) {
	clear()

	_, err := GetUser("alice", "fubar")
	if err == nil {
		// t.Error says the test fails
		t.Error("Got non-existing user", err)
		return
	}

	_, err = InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	var _, error = InitUser("alice", "password")
	if error == nil {
		// t.Error says the test fails
		t.Error("Failed to validate credentials", error)
		return
	}
}

func TestUserIntegrity(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	var user = *u

	var hash = userlib.Hash([]byte("user/" + user.Username))
	var key = bytesToUUID(hash[:])

	user.Username = "tampered"

	j, err := json.Marshal(&u)
	userlib.DatastoreSet(key, j)

	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	var _, error = GetUser("alice", "fubar")
	if error == nil {
		// t.Error says the test fails
		t.Error("Failed to validate integrity", error)
		return
	}
}

func TestUserInstances(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	var user, error = GetUser("alice", "fubar")
	if error != nil {
		// t.Error says the test fails
		t.Error("Failed to get user", error)
		return
	}

	if !reflect.DeepEqual(u, user) {
		t.Error("Instances of 2 same users are not equal")
	}
}

func TestInvalidCredential(t *testing.T) {
	clear()

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	var _, error = GetUser("alice", "wrong password")
	if error == nil {
		// t.Error says the test fails
		t.Error("Failed to validate credentials", error)
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

	v := []byte("aaaaa")
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

	u.AppendFile("file1", []byte(" hello"))
	u.AppendFile("file1", []byte(" world"))
	u.AppendFile("file1", []byte(" "))
	u.AppendFile("file1", []byte(""))

	v3, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error("Failed to load file", err2)
		return
	}

	if reflect.DeepEqual(v3, v2) {
		t.Error("File wasn't appended to", v3, v2)
	}
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

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}
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

	v2, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}
	v3, err := u2.LoadFile("file2")
	if err == nil {
		t.Error("Access is not revoked, file:", v3)
	}
}

func TestTokenRevoke(t *testing.T) {
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

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}
	err = u2.ReceiveFile("file3", "alice", magic_string)
	if err == nil {
		t.Error("Access token not revoked", err)
	}
}
