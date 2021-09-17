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
	keyring keyctl.Keyring
	perm    keyctl.KeyPerm
}

func init() {
	supportedBackends[KeyCtlBackend] = opener(func(cfg Config) (Keyring, error) {
		keyring := keyctlKeyring{}
		if cfg.KeyCtlPerm > 0 {
			keyring.perm = keyctl.KeyPerm(cfg.KeyCtlPerm)
		}

		parent, err := GetKeyringForScope(cfg.KeyCtlScope)
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
				namedKeyring, err = keyring.createNamedKeyring(parent, cfg.ServiceName)
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
	if err != nil {
		if errors.Is(err, syscall.ENOKEY) {
			return Item{}, ErrKeyNotFound
		}
		return Item{}, err
	}

	data, err := key.Get()
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
	if k.perm == 0 {
		// Keep the default permissions (alswrv-----v------------)
		_, err := k.keyring.Add(item.Key, item.Data)
		return err
	}

	// By default we loose possession of the key in anything above the session keyring.
	// Together with the default permissions (which cannot be changed during creation) we
	// cannot change the permissions without possessing the key. Therefore, create the
	// key in the session keyring, change permissions and then link to the target
	// keyring and unlink from the intermediate keyring again.
	session, err := keyctl.SessionKeyring()
	if err != nil {
		return fmt.Errorf("accessing session keyring failed: %v", err)
	}

	key, err := session.Add(item.Key, item.Data)
	if err != nil {
		return fmt.Errorf("adding key to session failed: %v", err)
	}

	if err := keyctl.SetPerm(key, k.perm); err != nil {
		return fmt.Errorf("setting permission %q failed: %v", k.perm, err)
	}

	if err := keyctl.Link(k.keyring, key); err != nil {
		return fmt.Errorf("linking key to keyring failed: %v", err)
	}

	if err := keyctl.Unlink(session, key); err != nil {
		return fmt.Errorf("unlinking key from session failed: %v", err)
	}

	return nil
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

func (k *keyctlKeyring) createNamedKeyring(parent keyctl.Keyring, name string) (keyctl.NamedKeyring, error) {
	if k.perm == 0 {
		// Keep the default permissions (alswrv-----v------------)
		return keyctl.CreateKeyring(parent, name)
	}

	// By default we loose possession of the keyring in anything above the session keyring.
	// Together with the default permissions (which cannot be changed during creation) we
	// cannot change the permissions without possessing the keyring. Therefore, create the
	// keyring linked to the session keyring, change permissions and then link to the target
	// keyring and unlink from the intermediate keyring again.
	session, err := keyctl.SessionKeyring()
	if err != nil {
		return nil, fmt.Errorf("accessing session keyring failed: %v", err)
	}

	keyring, err := keyctl.CreateKeyring(session, name)
	if err != nil {
		return nil, fmt.Errorf("creating keyring failed: %v", err)
	}

	if err := keyctl.SetPerm(keyring, k.perm); err != nil {
		return nil, fmt.Errorf("setting permission %q failed: %v", k.perm, err)
	}

	if err := keyctl.Link(k.keyring, keyring); err != nil {
		return nil, fmt.Errorf("linking keyring failed: %v", err)
	}

	if err := keyctl.Unlink(session, keyring); err != nil {
		return nil, fmt.Errorf("unlinking keyring from session failed: %v", err)
	}

	return keyring, nil
}

func GetKeyringForScope(scope string) (keyctl.Keyring, error) {
	switch scope {
	case "user":
		return keyctl.UserSessionKeyring()
	case "group":
		// Not yet implemented in the kernel
		// parent, err = keyctl.GroupKeyring()
		return nil, fmt.Errorf("scope %q not yet implemented", scope)
	case "session":
		return keyctl.SessionKeyring()
	case "process":
		return keyctl.ProcessKeyring()
	case "thread":
		return keyctl.ThreadKeyring()
	default:
		return nil, fmt.Errorf("unknown scope %q", scope)
	}
}
