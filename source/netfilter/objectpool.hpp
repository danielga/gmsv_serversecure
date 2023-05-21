#ifndef NETFILTER_OBJECTPOOL_HPP
#define NETFILTER_OBJECTPOOL_HPP

#pragma once

#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <vector>

/// A pool of objects of a specific class, with a fixed sized and optional
/// ordering. Very poor at inserting at the beginning and randomly, extremely
/// fast at inserting at the end, making it excellent to deal with time-based
/// ascending order.
template <typename ObjectClass, size_t ObjectCount,
          class ObjectComparer = std::less<ObjectClass>>
class ObjectPool {
public:
  using OptionalObjectAndIndexPair =
      std::optional<std::pair<std::reference_wrapper<ObjectClass>, size_t>>;

  ObjectPool() {
    m_objects.resize(Capacity());

    for (size_t k = 0; k < Capacity() - 1; ++k) {
      auto object = &m_objects[k];
      object->m_index = k;
      object->m_next_free_object = &m_objects[k + 1];
    }

    auto last_object = &m_objects.back();
    last_object->m_index = Capacity() - 1;
    last_object->m_next_free_object = nullptr;

    m_next_free_object = &m_objects.front();
  }

  /// Returns the maximum number of objects in the pool.
  [[nodiscard]] constexpr size_t Capacity() const { return ObjectCount; }

  /// Returns the number of locked objects in the pool.
  [[nodiscard]] size_t Size() const { return m_locked_objects; }

  /// Returns the const object reference associated to the given index.
  const ObjectClass &operator[](const size_t index) const {
    return ValidateAndGetObjectWrapper(index)->m_object;
  }

  /// Returns the object reference associated to the given index.
  ObjectClass &operator[](const size_t index) {
    return ValidateAndGetObjectWrapper(index)->m_object;
  }

  /// Unlocks all objects and resets this pool.
  void Clear() {
    for (size_t k = 0; k < Capacity() - 1; ++k) {
      auto object = &m_objects[k];
      object->m_index = k;
      object->m_next_free_object = &m_objects[k + 1];
      object->m_previous_ordered_object = nullptr;
      object->m_next_ordered_object = nullptr;
    }

    auto last_object = &m_objects.back();
    last_object->m_index = Capacity() - 1;
    last_object->m_next_free_object = nullptr;

    m_locked_objects = 0;
    m_next_free_object = &m_objects.front();

    m_first_ordered_object = nullptr;
    m_last_ordered_object = nullptr;
  }

  /// Returns true if there are unlocked objects, false otherwise.
  [[nodiscard]] bool HasLockableObjects() const {
    return m_next_free_object != nullptr;
  }

  /// Returns a pair of a locked object reference and its index, or no value if
  /// there are no lockable objects available.
  OptionalObjectAndIndexPair LockObject() {
    if (m_next_free_object == nullptr) {
      return {};
    }

    ++m_locked_objects;

    ObjectWrapper *object_wrapper = m_next_free_object;
    m_next_free_object = object_wrapper->m_next_free_object;
    object_wrapper->m_next_free_object = nullptr;

    return std::make_pair(std::ref(object_wrapper->m_object),
                          object_wrapper->m_index);
  }

  /// Unlocks a previously locked object by its index, throwing an exception if
  /// the index is larger than the capacity or if the object wasn't locked.
  void UnlockObject(const size_t index) {
    ObjectWrapper *object_wrapper = ValidateAndGetObjectWrapper(index);

    --m_locked_objects;

    if (m_next_free_object != nullptr) {
      object_wrapper->m_next_free_object = m_next_free_object;
    }

    m_next_free_object = object_wrapper;

    RemoveObjectFromOrderedList(object_wrapper);
  }

  /// Returns the first ordered object, if placement of objects was updated.
  OptionalObjectAndIndexPair GetFirstObject() {
    if (m_first_ordered_object == nullptr) {
      return {};
    }

    return std::make_pair(std::ref(m_first_ordered_object->m_object),
                          m_first_ordered_object->m_index);
  }

  /// Returns the last ordered object, if placement of objects was updated.
  OptionalObjectAndIndexPair GetLastObject() {
    if (m_last_ordered_object == nullptr) {
      return {};
    }

    return std::make_pair(std::ref(m_last_ordered_object->m_object),
                          m_last_ordered_object->m_index);
  }

  /// Returns the previous ordered object of the given object index, if
  /// placement of objects was updated, throwing an exception if the index is
  /// larger than the capacity or if the object wasn't locked.
  OptionalObjectAndIndexPair GetPreviousObject(const size_t index) {
    ObjectWrapper *object_wrapper = ValidateAndGetObjectWrapper(index);
    ObjectWrapper *previous_object_wrapper =
        object_wrapper->m_previous_ordered_object;
    if (previous_object_wrapper == nullptr) {
      return {};
    }

    return std::make_pair(std::ref(previous_object_wrapper->m_object),
                          previous_object_wrapper->m_index);
  }

  /// Returns the next ordered object of the given object index, if placement of
  /// objects was updated, throwing an exception if the index is larger than the
  /// capacity or if the object wasn't locked.
  OptionalObjectAndIndexPair GetNextObject(const size_t index) {
    ObjectWrapper *object_wrapper = ValidateAndGetObjectWrapper(index);
    ObjectWrapper *next_object_wrapper = object_wrapper->m_next_ordered_object;
    if (next_object_wrapper == nullptr) {
      return {};
    }

    return std::make_pair(std::ref(next_object_wrapper->m_object),
                          next_object_wrapper->m_index);
  }

  /// Updates the placement of the given object index using the configured
  /// comparer, throwing an exception if the index is larger than the capacity
  /// or if the object wasn't locked.
  void UpdateObjectPlacement(const size_t index) {
    ObjectWrapper *object_wrapper = ValidateAndGetObjectWrapper(index);
    RemoveObjectFromOrderedList(object_wrapper);
    AddObjectToOrderedList(object_wrapper);
  }

private:
  struct ObjectWrapper {
    size_t m_index = 0;
    ObjectWrapper *m_next_free_object = nullptr;
    ObjectWrapper *m_previous_ordered_object = nullptr;
    ObjectWrapper *m_next_ordered_object = nullptr;
    ObjectClass m_object;
  };

  [[nodiscard]] const ObjectWrapper *
  ValidateAndGetObjectWrapper(const size_t index) const {
    if (index >= Capacity()) {
      throw std::out_of_range("object pool index is out of range");
    }

    const ObjectWrapper *object_wrapper = &m_objects[index];
    if (object_wrapper->m_next_free_object != nullptr) {
      throw std::invalid_argument("object pool index is not locked");
    }

    return object_wrapper;
  }

  ObjectWrapper *ValidateAndGetObjectWrapper(const size_t index) {
    if (index >= Capacity()) {
      throw std::out_of_range("object pool index is out of range");
    }

    ObjectWrapper *object_wrapper = &m_objects[index];
    if (object_wrapper->m_next_free_object != nullptr) {
      throw std::invalid_argument("object pool index is not locked");
    }

    return object_wrapper;
  }

  ObjectWrapper *FindPlacementForObject(const ObjectClass &object) {
    ObjectWrapper *current_wrapper = m_last_ordered_object;
    while (current_wrapper != nullptr) {
      if (m_comparer(current_wrapper->m_object, object)) {
        return current_wrapper->m_next_ordered_object;
      }

      current_wrapper = current_wrapper->m_previous_ordered_object;
    }

    return m_first_ordered_object;
  }

  void AddObjectToOrderedList(ObjectWrapper *object_wrapper) {
    ObjectWrapper *next_object =
        FindPlacementForObject(object_wrapper->m_object);
    ObjectWrapper *previous_object =
        next_object != nullptr ? next_object->m_previous_ordered_object
                               : m_last_ordered_object;

    object_wrapper->m_previous_ordered_object = previous_object;
    object_wrapper->m_next_ordered_object = next_object;

    if (next_object == m_first_ordered_object) {
      m_first_ordered_object = object_wrapper;
    }

    if (next_object == nullptr) {
      m_last_ordered_object = object_wrapper;
    }

    if (previous_object != nullptr) {
      previous_object->m_next_ordered_object = object_wrapper;
    }

    if (next_object != nullptr) {
      next_object->m_previous_ordered_object = object_wrapper;
    }
  }

  void RemoveObjectFromOrderedList(ObjectWrapper *object_wrapper) {
    auto previous_object = object_wrapper->m_previous_ordered_object;
    auto next_object = object_wrapper->m_next_ordered_object;

    if (object_wrapper == m_first_ordered_object) {
      m_first_ordered_object = next_object;
    }

    if (object_wrapper == m_last_ordered_object) {
      m_last_ordered_object = previous_object;
    }

    if (previous_object != nullptr) {
      previous_object->m_next_ordered_object = next_object;
    }

    if (next_object != nullptr) {
      next_object->m_previous_ordered_object = previous_object;
    }

    object_wrapper->m_previous_ordered_object = nullptr;
    object_wrapper->m_next_ordered_object = nullptr;
  }

  std::vector<ObjectWrapper> m_objects;
  size_t m_locked_objects = 0;
  ObjectWrapper *m_next_free_object = nullptr;

  const ObjectComparer m_comparer{};
  ObjectWrapper *m_first_ordered_object = nullptr;
  ObjectWrapper *m_last_ordered_object = nullptr;

  static_assert(ObjectCount < (std::numeric_limits<size_t>::max)());
};

#endif // NETFILTER_OBJECTPOOL_HPP
