package cache

import (
	"container/list"
	"sync"
)

type LruElement[K comparable, V comparable] struct {
	Key   K `json:"key"`
	Value V `json:"value"`
}

// Lru simple, fast lru cache implementation
type Lru[K comparable, V comparable] interface {
	Get(key K) (value V, ok bool)
	GetKeyFromValue(value V) (key K, ok bool)
	PeekKeyFromValue(value V) (key K, ok bool) // Peek means check but NOT bring to top
	Put(key K, value V)
	Dump() []*LruElement[K, V]
}

type lru[K, V comparable] struct {
	capacity         int
	doubleLinkedList *list.List
	keyToElement     *sync.Map
	valueToElement   *sync.Map
	mu               *sync.Mutex
}

// NewLru initializes a lru cache
func NewLru[K comparable, V comparable](cap int) Lru[K, V] {
	return &lru[K, V]{
		capacity:         cap,
		doubleLinkedList: list.New(),
		keyToElement:     new(sync.Map),
		valueToElement:   new(sync.Map),
		mu:               new(sync.Mutex),
	}
}

func (l *lru[K, V]) Get(key K) (value V, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if v, ok := l.keyToElement.Load(key); ok {
		element := v.(*list.Element)
		l.doubleLinkedList.MoveToFront(element)
		return element.Value.(*LruElement[K, V]).Value, true
	}
	var Vz V
	return Vz, false
}

func (l *lru[K, V]) GetKeyFromValue(value V) (key K, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if k, ok := l.valueToElement.Load(value); ok {
		element := k.(*list.Element)
		l.doubleLinkedList.MoveToFront(element)
		return element.Value.(*LruElement[K, V]).Key, true
	}
	var Kz K
	return Kz, false
}

func (l *lru[K, V]) PeekKeyFromValue(value V) (key K, ok bool) {
	if k, ok := l.valueToElement.Load(value); ok {
		element := k.(*list.Element)
		return element.Value.(*LruElement[K, V]).Key, true
	}
	var Kz K
	return Kz, false
}

func (l *lru[K, V]) Put(key K, value V) {
	l.mu.Lock()
	e := &LruElement[K, V]{key, value}
	if v, ok := l.keyToElement.Load(key); ok {
		element := v.(*list.Element)
		element.Value = e
		l.doubleLinkedList.MoveToFront(element)
	} else {
		element := l.doubleLinkedList.PushFront(e)
		l.keyToElement.Store(key, element)
		l.valueToElement.Store(value, element)
		if l.doubleLinkedList.Len() > l.capacity {
			toBeRemove := l.doubleLinkedList.Back()
			l.doubleLinkedList.Remove(toBeRemove)
			l.keyToElement.Delete(toBeRemove.Value.(*LruElement[K, V]).Key)
			l.valueToElement.Delete(toBeRemove.Value.(*LruElement[K, V]).Value)
		}
	}
	l.mu.Unlock()
}

func (l *lru[K, V]) Dump() []*LruElement[K, V] {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]*LruElement[K, V], 0, l.doubleLinkedList.Len())
	for e := l.doubleLinkedList.Front(); e != nil; e = e.Next() {
		result = append(result, e.Value.(*LruElement[K, V]))
	}
	return result
}
