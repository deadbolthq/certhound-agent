//go:build !windows

package renewal

import "fmt"

// ImportPFXToStore is a no-op stub for non-Windows platforms. The config
// layer rejects WindowsCertStore entries before we ever reach runtime on
// these platforms, so this should never be called — the explicit error
// is a belt-and-suspenders guard.
func ImportPFXToStore(storeSpec string, certBundlePEM []byte, key interface{}, domains []string) error {
	return fmt.Errorf("WindowsCertStore is not supported on this platform")
}
