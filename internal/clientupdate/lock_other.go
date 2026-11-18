//go:build !linux && !darwin

package clientupdate

import "errors"

func acquireLock(string) (func(), error) {
	return nil, errors.New("updater locking requires Linux or Darwin")
}
