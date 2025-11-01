package manifest

import "fmt"

// DifferenceType represents the type of difference between entities
type DifferenceType int

const (
	// DiffMissingInA indicates entity exists in B but not in A
	DiffMissingInA DifferenceType = iota
	// DiffMissingInB indicates entity exists in A but not in B
	DiffMissingInB
	// DiffChecksumMismatch indicates entities have different checksums
	DiffChecksumMismatch
	// DiffTypeMismatch indicates entities have different types (file vs directory)
	DiffTypeMismatch
)

// String returns the string representation of the difference type
func (d DifferenceType) String() string {
	switch d {
	case DiffMissingInA:
		return "missing_in_a"
	case DiffMissingInB:
		return "missing_in_b"
	case DiffChecksumMismatch:
		return "checksum_mismatch"
	case DiffTypeMismatch:
		return "type_mismatch"
	default:
		return "unknown"
	}
}

// EntityDifference represents a specific difference between two manifests
type EntityDifference struct {
	Name           string
	Type           DifferenceType
	ExpectedEntity *Entity
	ActualEntity   *Entity
}

// CompareManifests compares two manifests and returns their differences
// Returns (identical, differences, error)
func CompareManifests(a, b *Manifest) (bool, []EntityDifference, error) {
	if a == nil || b == nil {
		return false, nil, fmt.Errorf("cannot compare nil manifests")
	}

	// Create maps for easier comparison
	entitiesA := make(map[string]Entity)
	for _, entity := range a.Entities {
		entitiesA[entity.Name] = entity
	}

	entitiesB := make(map[string]Entity)
	for _, entity := range b.Entities {
		entitiesB[entity.Name] = entity
	}

	differences := make([]EntityDifference, 0)

	// Check for entities in A but not in B
	for name, entityA := range entitiesA {
		if entityB, exists := entitiesB[name]; !exists {
			differences = append(differences, EntityDifference{
				Name:           name,
				Type:           DiffMissingInB,
				ExpectedEntity: &entityA,
				ActualEntity:   nil,
			})
		} else {
			// Entity exists in both, check for differences
			if entityA.IsDir != entityB.IsDir {
				differences = append(differences, EntityDifference{
					Name:           name,
					Type:           DiffTypeMismatch,
					ExpectedEntity: &entityA,
					ActualEntity:   &entityB,
				})
			} else if entityA.Checksum != entityB.Checksum {
				differences = append(differences, EntityDifference{
					Name:           name,
					Type:           DiffChecksumMismatch,
					ExpectedEntity: &entityA,
					ActualEntity:   &entityB,
				})
			}
		}
	}

	// Check for entities in B but not in A
	for name, entityB := range entitiesB {
		if _, exists := entitiesA[name]; !exists {
			differences = append(differences, EntityDifference{
				Name:           name,
				Type:           DiffMissingInA,
				ExpectedEntity: nil,
				ActualEntity:   &entityB,
			})
		}
	}

	return len(differences) == 0, differences, nil
}
