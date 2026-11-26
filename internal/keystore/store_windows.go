//go:build windows

package keystore

// Windows backends, written against the standard library's syscall package
// (no golang.org/x/sys): the registry location QSettings("HashHarvest",
// "HashHarvest") uses, and Credential Manager entries laid out the way
// python-keyring's WinVaultKeyring writes them.

import (
	"errors"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const registryPath = `Software\` + service + `\` + service

func init() {
	settings = backend{
		get:    func() (string, error) { return regGet(registryPath, keyName) },
		set:    func(v string) error { return regSet(registryPath, keyName, v) },
		remove: func() error { return regDelete(registryPath, keyName) },
	}
	keychain = &backend{
		get:    func() (string, error) { return credGet(service, keyName) },
		set:    func(v string) error { return credWrite(service, keyName, v) },
		remove: func() error { return credRemove(service, keyName) },
	}
}

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyEx = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueEx  = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValue = advapi32.NewProc("RegDeleteValueW")
	procCredRead       = advapi32.NewProc("CredReadW")
	procCredWrite      = advapi32.NewProc("CredWriteW")
	procCredDelete     = advapi32.NewProc("CredDeleteW")
	procCredFree       = advapi32.NewProc("CredFree")
)

const (
	keySetValue      = 0x0002
	regSZ            = 1
	credTypeGeneric  = 1
	credPersistEnter = 3 // CRED_PERSIST_ENTERPRISE, python-keyring's default
	errNotFound      = syscall.Errno(1168)
)

// regGet returns "" when the key or value does not exist.
func regGet(path, name string) (string, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, pathPtr, 0, syscall.KEY_READ, &key); err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return "", nil
		}
		return "", err
	}
	defer syscall.RegCloseKey(key)

	var typ, size uint32
	if err := syscall.RegQueryValueEx(key, namePtr, nil, &typ, nil, &size); err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return "", nil
		}
		return "", err
	}
	if typ != regSZ || size < 2 {
		return "", nil
	}
	buf := make([]uint16, (size+1)/2)
	if err := syscall.RegQueryValueEx(key, namePtr, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return "", err
	}
	return syscall.UTF16ToString(buf), nil
}

func regSet(path, name, value string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	data, err := syscall.UTF16FromString(value) // NUL-terminated
	if err != nil {
		return err
	}
	var key syscall.Handle
	if rc, _, _ := procRegCreateKeyEx.Call(uintptr(syscall.HKEY_CURRENT_USER), uintptr(unsafe.Pointer(pathPtr)),
		0, 0, 0, keySetValue, 0, uintptr(unsafe.Pointer(&key)), 0); rc != 0 {
		return syscall.Errno(rc)
	}
	defer syscall.RegCloseKey(key)
	if rc, _, _ := procRegSetValueEx.Call(uintptr(key), uintptr(unsafe.Pointer(namePtr)), 0, regSZ,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2)); rc != 0 {
		return syscall.Errno(rc)
	}
	return nil
}

func regDelete(path, name string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, pathPtr, 0, keySetValue, &key); err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return nil
		}
		return err
	}
	defer syscall.RegCloseKey(key)
	if rc, _, _ := procRegDeleteValue.Call(uintptr(key), uintptr(unsafe.Pointer(namePtr))); rc != 0 &&
		syscall.Errno(rc) != syscall.ERROR_FILE_NOT_FOUND {
		return syscall.Errno(rc)
	}
	return nil
}

// credential mirrors the Win32 CREDENTIALW structure.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for *(*uint16)(unsafe.Add(unsafe.Pointer(p), 2*n)) != 0 {
		n++
	}
	return string(utf16.Decode(unsafe.Slice(p, n)))
}

// credRead returns the user name and secret stored under target; found is
// false when there is no such credential.
func credRead(target string) (user, secret string, found bool, err error) {
	targetPtr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return "", "", false, err
	}
	var cred *credential
	rc, _, callErr := procCredRead.Call(uintptr(unsafe.Pointer(targetPtr)), credTypeGeneric, 0,
		uintptr(unsafe.Pointer(&cred)))
	if rc == 0 {
		if callErr == errNotFound {
			return "", "", false, nil
		}
		return "", "", false, callErr
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(cred)))

	// The secret is stored as UTF-16LE without a terminator.
	blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
	units := make([]uint16, len(blob)/2)
	for i := range units {
		units[i] = uint16(blob[2*i]) | uint16(blob[2*i+1])<<8
	}
	return utf16PtrToString(cred.UserName), string(utf16.Decode(units)), true, nil
}

// credGet looks under the service name first, then under the compound
// "user@service" name python-keyring falls back to.
func credGet(service, user string) (string, error) {
	for _, target := range []string{service, user + "@" + service} {
		owner, secret, found, err := credRead(target)
		if err != nil {
			return "", err
		}
		if found && owner == user {
			return secret, nil
		}
	}
	return "", nil
}

// ponytail: always writes under the plain service name. python-keyring
// first moves an existing credential with a different user name aside;
// HashHarvest only ever stores one user under this service.
func credWrite(service, user, secret string) error {
	targetPtr, err := syscall.UTF16PtrFromString(service)
	if err != nil {
		return err
	}
	userPtr, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	commentPtr, _ := syscall.UTF16PtrFromString("Stored by HashHarvest")
	if secret == "" {
		return errors.New("cannot store an empty key")
	}
	units := utf16.Encode([]rune(secret))
	blob := make([]byte, len(units)*2)
	for i, u := range units {
		blob[2*i], blob[2*i+1] = byte(u), byte(u>>8)
	}
	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         targetPtr,
		Comment:            commentPtr,
		CredentialBlobSize: uint32(len(blob)),
		CredentialBlob:     &blob[0],
		Persist:            credPersistEnter,
		UserName:           userPtr,
	}
	if rc, _, callErr := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0); rc == 0 {
		return callErr
	}
	return nil
}

func credRemove(service, user string) error {
	for _, target := range []string{service, user + "@" + service} {
		owner, _, found, err := credRead(target)
		if err != nil {
			return err
		}
		if !found || owner != user {
			continue
		}
		targetPtr, err := syscall.UTF16PtrFromString(target)
		if err != nil {
			return err
		}
		if rc, _, callErr := procCredDelete.Call(uintptr(unsafe.Pointer(targetPtr)), credTypeGeneric, 0); rc == 0 {
			return callErr
		}
	}
	return nil
}
