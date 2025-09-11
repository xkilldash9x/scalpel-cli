package providers

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

// TestStore_Add verifies adding providers, including duplicate and invalid input checks.
func TestStore_Add(t *testing.T) {
	store := NewStore()

	p1 := Provider{ID: "1", Name: "AWS", Type: "IaaS"}

	// 1. Test successful addition
	if err := store.Add(p1); err != nil {
		t.Fatalf("Expected no error on first add, got %v", err)
	}

	// 2. Test duplicate addition
	p1Duplicate := Provider{ID: "1", Name: "Amazon Web Services", Type: "IaaS"}
	if err := store.Add(p1Duplicate); err != ErrAlreadyExists {
		t.Errorf("Expected ErrAlreadyExists, got %v", err)
	}

	// 3. Test invalid input (empty Name)
	invalidP := Provider{ID: "2", Name: "", Type: "PaaS"}
	if err := store.Add(invalidP); err != ErrInvalidInput {
		t.Errorf("Expected ErrInvalidInput, got %v", err)
	}
}

// TestStore_Get verifies retrieving existing and non-existent providers.
func TestStore_Get(t *testing.T) {
	store := NewStore()
	p1 := Provider{ID: "1", Name: "AWS", Type: "IaaS"}
	store.Add(p1)

	// 1. Test getting an existing provider
	got, err := store.Get("1")
	if err != nil {
		t.Fatalf("Expected no error on Get, got %v", err)
	}
	// Use DeepEqual for struct comparison
	if !reflect.DeepEqual(got, p1) {
		t.Errorf("Get() = %v, want %v", got, p1)
	}

	// 2. Test getting a non-existent provider
	_, err = store.Get("99")
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

// TestStore_List verifies the listing functionality and sorting order.
func TestStore_List(t *testing.T) {
	store := NewStore()

	// 1. Test empty list
	if len(store.List()) != 0 {
		t.Errorf("Expected empty list, got %d items", len(store.List()))
	}

	// Add providers out of order
	p1 := Provider{ID: "1", Name: "AWS", Type: "IaaS"}
	p2 := Provider{ID: "2", Name: "Azure", Type: "IaaS"}
	p0 := Provider{ID: "0", Name: "GCP", Type: "IaaS"}
	store.Add(p1)
	store.Add(p2)
	store.Add(p0)

	// 2. Test listing all providers (must be sorted by ID)
	want := []Provider{p0, p1, p2}
	got := store.List()

	if !reflect.DeepEqual(got, want) {
		t.Errorf("List() = %v, want %v (check sorting)", got, want)
	}
}

// TestStore_Update verifies updating providers.
func TestStore_Update(t *testing.T) {
	store := NewStore()
	p1 := Provider{ID: "1", Name: "AWS", Type: "IaaS"}
	store.Add(p1)

	// 1. Test successful update
	p1Updated := Provider{ID: "1", Name: "Amazon Web Services", Type: "Cloud"}
	if err := store.Update(p1Updated); err != nil {
		t.Fatalf("Expected no error on Update, got %v", err)
	}

	// Verify the update took effect
	got, _ := store.Get("1")
	if !reflect.DeepEqual(got, p1Updated) {
		t.Errorf("After Update, got %v, want %v", got, p1Updated)
	}

	// 2. Test updating a non-existent provider
	pNotFound := Provider{ID: "99", Name: "Ghost", Type: "SaaS"}
	if err := store.Update(pNotFound); err != ErrNotFound {
		t.Errorf("Expected ErrNotFound on Update, got %v", err)
	}

	// 3. Test invalid update input
	pInvalid := Provider{ID: "1", Name: "", Type: "Cloud"}
	if err := store.Update(pInvalid); err != ErrInvalidInput {
		t.Errorf("Expected ErrInvalidInput on Update, got %v", err)
	}
}

// TestStore_Delete verifies the deletion of providers.
func TestStore_Delete(t *testing.T) {
	store := NewStore()
	p1 := Provider{ID: "1", Name: "AWS", Type: "IaaS"}
	store.Add(p1)

	// 1. Test successful deletion
	if err := store.Delete("1"); err != nil {
		t.Fatalf("Expected no error on Delete, got %v", err)
	}

	// Verify deletion
	_, err := store.Get("1")
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound after deletion, got %v", err)
	}

	// 2. Test deleting a non-existent provider
	if err := store.Delete("99"); err != ErrNotFound {
		t.Errorf("Expected ErrNotFound when deleting non-existent ID, got %v", err)
	}
}

// TestStore_Concurrency verifies thread safety by performing concurrent writes and reads.
func TestStore_Concurrency(t *testing.T) {
	store := NewStore()
	concurrencyLevel := 100
	var wg sync.WaitGroup

	// Concurrently add providers (Writers)
	for i := 0; i < concurrencyLevel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("%d", i)
			p := Provider{ID: id, Name: fmt.Sprintf("Provider %d", i), Type: "Test"}
			if err := store.Add(p); err != nil {
				// t.Errorf can be safely called from concurrent goroutines in modern Go testing
				t.Errorf("Concurrent Add failed: %v", err)
			}
		}(i)
	}

	// Concurrently list providers (Readers)
	for i := 0; i < concurrencyLevel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.List()
		}()
	}

	wg.Wait()

	// Check if t has marked the test as failed due to errors in goroutines
	if t.Failed() {
		return
	}

	// Verify the final state
	if len(store.List()) != concurrencyLevel {
		t.Errorf("Expected %d providers after concurrent addition, got %d", concurrencyLevel, len(store.List()))
	}
}