package adapter

import "github.com/seolcu/hostveil/internal/domain"

type Adapter interface {
	Name() string
	Run(target string) ([]domain.Finding, error)
	IsAvailable() bool
}

func All() []Adapter {
	return []Adapter{
		&TrivyAdapter{},
		&LynisAdapter{},
		&GitleaksAdapter{},
	}
}
