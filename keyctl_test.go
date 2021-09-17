//go:build linux
// +build linux

package keyring_test

import (
	"errors"
	"math/rand"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/jsipprell/keyctl"

	"github.com/99designs/keyring"
)

var ringname = getRandomKeyringName(16)

func getRandomKeyringName(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	rand.Seed(time.Now().UnixNano())

	buf := make([]byte, length)
	for i := range buf {
		buf[i] = charset[rand.Intn(len(charset))]
	}
	return "keyctl_test_" + string(buf)
}

func doesNamedKeyringExist() (bool, error) {
	parent, err := keyctl.SessionKeyring()
	if err != nil {
		return false, err
	}
	_, err = keyctl.OpenKeyring(parent, ringname)
	if errors.Is(err, syscall.ENOKEY) {
		return false, nil
	}
	return err == nil, err
}

func cleanupNamedKeyring() {
	parent, err := keyctl.SessionKeyring()
	if err != nil {
		return
	}
	named, err := keyctl.OpenKeyring(parent, ringname)
	if err != nil {
		return
	}

	_ = keyctl.UnlinkKeyring(named)
}

func TestKeyCtlIsAvailable(t *testing.T) {
	found := false
	backends := keyring.AvailableBackends()
	for _, b := range backends {
		if b == keyring.KeyCtlBackend {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("keyctl backends not among %v", backends)
	}
}

func TestKeyCtlOpenFailWrongScope(t *testing.T) {
	failingScopes := []string{"", "group", "invalid"}
	for _, scope := range failingScopes {
		_, err := keyring.Open(keyring.Config{
			AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
			KeyCtlScope:     scope,
		})
		if err == nil {
			t.Fatalf("scope %q should fail", scope)
		}
	}
}

func TestKeyCtlOpen(t *testing.T) {
	scopes := []string{"user", "session", "process", "thread"}
	for _, scope := range scopes {
		_, err := keyring.Open(keyring.Config{
			AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
			KeyCtlScope:     scope,
		})
		if err != nil {
			t.Fatalf("scope %q failed: %v", scope, err)
		}
	}
}

func TestKeyCtlOpenNamed(t *testing.T) {
	if exists, err := doesNamedKeyringExist(); exists {
		t.Fatalf("ring %q already exists in scope %q", ringname, "user")
	} else if err != nil {
		t.Fatalf("checking for ring %q in scope %q failed: %v", ringname, "user", err)
	}
	t.Cleanup(cleanupNamedKeyring)

	_, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
		KeyCtlScope:     "session",
		ServiceName:     ringname,
	})
	if err != nil {
		t.Fatalf("opening ring %q in scope %q failed: %v", ringname, "user", err)
	}
}

func TestKeyCtlSet(t *testing.T) {
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
		KeyCtlScope:     "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	item1 := keyring.Item{
		Key:  "test",
		Data: []byte("loose lips sink ships"),
	}

	err = kr.Set(item1)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got keys: %v", keys)

	item2, err := kr.Get("test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(item1, item2) {
		t.Fatalf("Expected %#v, got %#v", item1, item2)
	}

	err = kr.Remove("test")
	if err != nil {
		t.Fatal(err)
	}

	_, err = kr.Get("test")
	if err != keyring.ErrKeyNotFound {
		t.Fatalf("Expected %v, got %v", keyring.ErrKeyNotFound, err)
	}
}

func TestKeyCtlSetNamed(t *testing.T) {
	if exists, err := doesNamedKeyringExist(); exists {
		t.Fatalf("ring %q already exists in scope %q", ringname, "user")
	} else if err != nil {
		t.Fatalf("checking for ring %q in scope %q failed: %v", ringname, "user", err)
	}
	t.Cleanup(cleanupNamedKeyring)

	kr, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
		KeyCtlScope:     "session",
		ServiceName:     ringname,
	})
	if err != nil {
		t.Fatal(err)
	}

	item1 := keyring.Item{
		Key:  "test",
		Data: []byte("loose lips sink ships"),
	}

	err = kr.Set(item1)
	if err != nil {
		t.Fatal(err)
	}

	item2, err := kr.Get("test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(item1, item2) {
		t.Fatalf("Expected %#v, got %#v", item1, item2)
	}

	err = kr.Remove("test")
	if err != nil {
		t.Fatal(err)
	}

	_, err = kr.Get("test")
	if err != keyring.ErrKeyNotFound {
		t.Fatalf("Expected %v, got %v", keyring.ErrKeyNotFound, err)
	}
}

func TestKeyCtlList(t *testing.T) {
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
		KeyCtlScope:     "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	item1 := keyring.Item{
		Key:  "test",
		Data: []byte("loose lips sink ships"),
	}

	err = kr.Set(item1)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if expected := []string{"test"}; !reflect.DeepEqual(keys, expected) {
		t.Fatalf("Unexpected keys, got %#v, expected %#v", keys, expected)
	}

	err = kr.Remove("test")
	if err != nil {
		t.Fatal(err)
	}
}

func TestKeyCtlGetNonExisting(t *testing.T) {
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
		KeyCtlScope:     "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = kr.Get("llamas")
	if err != keyring.ErrKeyNotFound {
		t.Fatal("Expected ErrKeyNotFound")
	}
}

func TestKeyCtlRemoveNonExisting(t *testing.T) {
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
		KeyCtlScope:     "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = kr.Remove("no-such-key")
	if err != keyring.ErrKeyNotFound {
		t.Fatal("Expected ErrKeyNotFound")
	}
}

func TestKeyCtlListEmptyKeyring(t *testing.T) {
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.KeyCtlBackend},
		KeyCtlScope:     "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}
