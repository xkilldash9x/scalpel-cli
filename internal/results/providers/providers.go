package providers

import (
	"errors"
	"sort"
	"sync"
)

// Provider represents the configuration for a specific provider.
type Provider struct {
	ID   string
	Name string
	Type string
}

// Define sentinel errors for better error handling by the caller.
var (
	ErrNotFound      = errors.New("provider not found")
	ErrAlreadyExists = errors.New("provider already exists")
	ErrInvalidInput  = errors.New("provider ID, Name, and Type cannot be empty")
)

// Store manages the collection of providers in memory.
type Store struct {
	// RWMutex allows multiple concurrent readers or a single exclusive writer.
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewStore creates a new, initialized provider store.
func NewStore() *Store {
	return &Store{
		providers: make(map[string]Provider),
	}
}

// validateProvider checks if the provider has all required fields.
func validateProvider(p Provider) error {
	if p.ID == "" || p.Name == "" || p.Type == "" {
		return ErrInvalidInput
	}
	return nil
}

// Add adds a new provider to the store.
func (s *Store) Add(p Provider) error {
	if err := validateProvider(p); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.providers[p.ID]; exists {
		return ErrAlreadyExists
	}

	s.providers[p.ID] = p
	return nil
}

// Get retrieves a provider by its ID.
func (s *Store) Get(id string) (Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	provider, exists := s.providers[id]
	if !exists {
		return Provider{}, ErrNotFound
	}

	return provider, nil
}

// List returns a list of all providers, sorted by ID for deterministic output.
func (s *Store) List() []Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]Provider, 0, len(s.providers))
	for _, provider := range s.providers {
		list = append(list, provider)
	}

	// Sort by ID
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})

	return list
}

// Update modifies an existing provider.
func (s *Store) Update(p Provider) error {
	if err := validateProvider(p); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.providers[p.ID]; !exists {
		return ErrNotFound
	}

	// Replace the existing provider with the new data
	s.providers[p.ID] = p
	return nil
}

// Delete removes a provider by its ID.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.providers[id]; !exists {
		return ErrNotFound
	}

	delete(s.providers, id)
	return nil
}