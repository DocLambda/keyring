//go:build linux
// +build linux

package keyring

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/jsipprell/keyctl"
)

type keyctlKeyring struct {
	name    string
	keyring keyctl.Keyring
}

func init() {
	supportedBackends[KeyCtlBackend] = opener(func(cfg Config) (Keyring, error) {
		var parent keyctl.Keyring
		var err error

		keyring := keyctlKeyring{name: cfg.ServiceName}
		switch cfg.KeyCtlScope {
		case "user":
			parent, err = keyctl.UserSessionKeyring()
		case "group":
			// Not yet implemented in the kernel
			// parent, err = keyctl.GroupKeyring()
			return nil, fmt.Errorf("scope %q not yet implemented", cfg.KeyCtlScope)
		case "session":
			parent, err = keyctl.SessionKeyring()
		case "process":
			parent, err = keyctl.ProcessKeyring()
		case "thread":
			parent, err = keyctl.ThreadKeyring()
		default:
			return nil, fmt.Errorf("unknown scope %q", cfg.KeyCtlScope)
		}
		if err != nil {
			return nil, fmt.Errorf("accessing %q keyring failed: %v", cfg.KeyCtlScope, err)
		}

		// Check for named keyrings
		keyring.keyring = parent
		if cfg.ServiceName != "" {
			namedKeyring, err := keyctl.OpenKeyring(parent, cfg.ServiceName)
			if err != nil {
				if !errors.Is(err, syscall.ENOKEY) {
					return nil, fmt.Errorf("opening named %q keyring failed: %v", cfg.KeyCtlScope, err)
				}

				// Keyring does not yet exist, create it
				namedKeyring, err = keyctl.CreateKeyring(parent, cfg.ServiceName)
				if err != nil {
					return nil, fmt.Errorf("creating named %q keyring failed: %v", cfg.KeyCtlScope, err)
				}
			}
			keyring.keyring = namedKeyring
		}

		return &keyring, nil
	})
}

func (k *keyctlKeyring) Get(name string) (Item, error) {
	key, err := k.keyring.Search(name)
	fmt.Printf("search err: %v\n", err)
	if err != nil {
		return Item{}, ErrKeyNotFound
	}

	info, err := key.Info()
	fmt.Printf("key info: %v (%v)\n", info, key)
	fmt.Printf("key info err: %v\n", err)

	data, err := key.Get()
	fmt.Printf("key get err: %v (%v)\n", err, data)
	if err != nil {
		return Item{}, err
	}

	item := Item{
		Key:  name,
		Data: data,
	}

	return item, nil
}

// GetMetadata for pass returns an error indicating that it's unsupported for this backend.
// TODO: We can deliver metadata different from the defined ones (e.g. permissions, expire-time, etc).
func (k *keyctlKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNotSupported
}

func (k *keyctlKeyring) Set(item Item) error {
	_, err := k.keyring.Add(item.Key, item.Data)
	return err
}

func (k *keyctlKeyring) Remove(name string) error {
	key, err := k.keyring.Search(name)
	if err != nil {
		return ErrKeyNotFound
	}

	return key.Unlink()
}

func (k *keyctlKeyring) Keys() ([]string, error) {
	results := []string{}

	references, err := keyctl.ListKeyring(k.keyring)
	if err != nil {
		return nil, err
	}

	for _, ref := range references {
		info, err := ref.Info()
		if err != nil {
			return nil, err
		}
		if info.Type == "key" {
			results = append(results, info.Name)
		}
	}

	return results, nil
}
