package main

import "github.com/seolcu/hostveil/internal/store"

// resolvePaths wraps store.Resolve so cmd/hostveil does not have to
// import the full store package just to get the on-disk layout.
func resolvePaths() (*store.Paths, error) {
	return store.Resolve()
}
