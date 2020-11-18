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
		return
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
		return
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

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("hello")
	u.StoreFile("file1", v)

	err = u.AppendFile("file1", []byte(" world"))
	if err != nil {
		t.Error("Append failed:", err)
		return
	}

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	if !reflect.DeepEqual([]byte("hello world"), v) {
		t.Error("Append failed:", v)
		return
	}
}

func TestManyAppends(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("hello")
	u.StoreFile("file1", v)

	for i := 0; i < 100; i++ {
		err = u.AppendFile("file1", []byte(" world"))
		if err != nil {
			t.Error("Append failed:", err)
			return
		}
	}

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	if reflect.DeepEqual([]byte("hello"), v) {
		t.Error("Append failed")
		return
	}
}

func TestInvalidAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	err = u.AppendFile("file2", []byte(" hello"))
	if err == nil {
		t.Error("Appended to nonexisting file")
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
		return
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
		return
	}
}

func TestInvalidShare(t *testing.T) {
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

	_, err = u.ShareFile("file1", "bob")
	if err == nil {
		t.Error("Shared a nonexisting file")
		return
	}
}

func TestShareNonexistingUser(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err = u.ShareFile("file1", "bob")
	if err == nil {
		t.Error("Shared with a nonexisting user")
		return
	}
}

func TestReceiveExistingFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2 := []byte("This is a test 2")
	u2.StoreFile("file2", v2)

	token, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", token)
	if err == nil {
		t.Error("Received a file with existing name")
		return
	}

	err = u2.ReceiveFile("new file", "alice", token)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}
}

func TestReceiveInvalidUserToken(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2 := []byte("This is a test 2")
	u2.StoreFile("file2", v2)

	token, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share", err)
		return
	}

	err = u2.ReceiveFile("new file", "wrong sender", token)
	if err == nil {
		t.Error("Received a file from invalid user")
		return
	}

	err = u2.ReceiveFile("new file", "alice", "wrong token")
	if err == nil {
		t.Error("Received with invalid token")
		return
	}
}

func TestReceiveMultipleIns(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u3, err := GetUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	token, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share", err)
		return
	}

	err = u2.ReceiveFile("new file", "alice", token)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}

	v2, err := u2.LoadFile("new file")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	v3, err := u3.LoadFile("new file")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	if !reflect.DeepEqual(v2, v3) {
		t.Error("Received is not same across multiple instances")
		return
	}
}

func TestRevokeNotReceived(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share", err)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}
}

func TestRevokeNotShared(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	err = u.RevokeFile("file1", "bob")
	if err == nil {
		t.Error("Revoked file without sharing")
		return
	}
}

func TestRevokeNotOwner(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u3, err := InitUser("bob2", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	token, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share", err)
		return
	}

	err = u2.ReceiveFile("new file", "alice", token)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}

	token2, err := u2.ShareFile("new file", "bob2")
	if err != nil {
		t.Error("Failed to share", err)
		return
	}

	err = u3.ReceiveFile("new file", "bob", token2)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}

	err = u2.RevokeFile("new file", "bob2")
	if err == nil {
		t.Error("Revoked file by owner")
		return
	}

	err = u.RevokeFile("new file", "bob2")
	if err == nil {
		t.Error("Revoked file from non-direct child")
		return
	}
}

func TestRevokeSharingTree(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u3, err := InitUser("bob2", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	token, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share", err)
		return
	}

	err = u2.ReceiveFile("new file", "alice", token)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}

	token2, err := u2.ShareFile("new file", "bob2")
	if err != nil {
		t.Error("Failed to share", err)
		return
	}

	err = u3.ReceiveFile("new file", "bob", token2)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}

	err = u.RevokeFile("file1", "bob2")
	if err == nil {
		t.Error("Revoked file from non-direct child")
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke from direct child", err)
		return
	}

	v1, err := u2.LoadFile("new file")
	if err == nil {
		t.Error("Not revoked file:", string(v1))
		return
	}

	v2, err := u3.LoadFile("new file")
	if err == nil {
		t.Error("Not revoked file:", string(v2))
		return
	}
}

func TestRevokeNotExistingFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	err = u.RevokeFile("wrong file", "bob")
	if err == nil {
		t.Error("Revoked non-existing file")
		return
	}
}

func TestRevokeNoAccess(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u.StoreFile("file1", []byte("file content"))

	err = u.RevokeFile("file1", "bob")
	if err == nil {
		t.Error("Revoked from user who didn't have access")
		return
	}
}

func TestAppendAfterRevoke(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u.StoreFile("file1", []byte("file content"))

	token, err := u.ShareFile("file1", "bob")

	err = u2.ReceiveFile("file1", "alice", token)
	if err != nil {
		t.Error("Failed to receive file")
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke from user", err)
		return
	}

	err = u2.AppendFile("file1", []byte("append"))
	if err == nil {
		t.Error("Appended to revoked file")
		return
	}
}

func TestShareAfterRevoke(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u.StoreFile("file1", []byte("file content"))

	token, err := u.ShareFile("file1", "bob")

	err = u2.ReceiveFile("file1", "alice", token)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke from user", err)
		return
	}

	_, err = u2.ShareFile("file1", "bob2")
	if err == nil {
		t.Error("Shared after file was revoked")
		return
	}
}
