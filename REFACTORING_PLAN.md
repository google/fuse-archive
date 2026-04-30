# Refactoring Plan: fuse-archive Modularization

This document outlines the strategy for refactoring `fuse-archive` from a monolithic file into a testable library structure, enabling "whitebox" unit testing and faster diagnostic checks (Valgrind/Sanitizers).

## Goal
To achieve architectural parity with `mount-zip` by separating core logic (tree building, indexing, metadata) from the FUSE frontend.

## Phases

### Phase 1: Infrastructure & Utilities
- Create a `lib/` directory.
- Update `Makefile` to support multiple source files and a library target (`libfusearchive.a`).
- Extract base utilities into `lib/util.h` and `lib/util.cc`:
    - `Timer`, `Beat`, `Logger`, `FileDescriptor`.
    - Error handling (`ExitCode`, `SafeAdd`).

### Phase 2: String & Metadata Management
- Extract `HashedString`, `HashedStringView`, and the `g_unique_strings` recycling logic into `lib/hashed_string.h/cc`.
- Extract `Hole` and `Holes` definitions.

### Phase 3: The Node Class
- Move the `Node` struct into `lib/node.h` and `lib/node.cc`.
- Encapsulate node-level logic: `AddChild`, `ComputePathHash`, `GetBlockCount`, `GetStat`.
- Standardize on `Node::Ptr` (RAII) management.

### Phase 4: The Tree Class (State Encapsulation)
- Create a `Tree` class in `lib/tree.h/cc` to replace global variables:
    - `g_root_node` -> `Tree::root_`
    - `g_nodes_by_path` -> `Tree::nodes_by_path_`
    - `BuildTree()` -> `Tree::Build()`
- This allows instantiating multiple independent filesystem trees for unit testing.

### Phase 5: FUSE Frontend Refactoring
- Refactor `fuse-archive.cc` to be a lightweight wrapper.
- Initialize a `Tree` instance and pass it to the FUSE operations.
- Update `readdir`, `getattr`, `read`, etc., to use the `Tree` and `Node` methods.

### Phase 6: Whitebox Testing
- Set up a `test/whitebox/` directory using `googletest`.
- Implement tests for:
    - Path collision handling.
    - Large tree construction performance.
    - Memory leak verification via Valgrind on the `Tree` logic alone.

## Revert Procedure
If any phase fails verification and cannot be resolved quickly:
`git reset --hard <last_stable_commit>`
