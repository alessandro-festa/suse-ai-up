package clients

// StoreEventType describes the kind of mutation a StoreEvent carries.
type StoreEventType string

const (
	StoreEventAdded   StoreEventType = "added"
	StoreEventUpdated StoreEventType = "updated"
	StoreEventDeleted StoreEventType = "deleted"
)

// StoreEvent is emitted by Watch and delivered to Subscribe handlers when a
// store mutates. Object is the post-change resource for Added/Updated and the
// pre-delete resource for Deleted; its concrete type matches the store
// (e.g. *models.AdapterResource for AdapterResourceStore).
//
// Phase 1 stores never emit events — these stubs exist so Phase 2's
// controller-runtime backed stores can fill them in without changing the
// interfaces or any callsites.
type StoreEvent struct {
	Type   StoreEventType
	Object interface{}
}

// StoreEventHandler is the callback shape accepted by Subscribe.
type StoreEventHandler func(StoreEvent)
