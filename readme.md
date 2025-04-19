# Rijndael (AES) Encryption Implementation
Student Name: Mingde Zhou
Student ID: D24128243
This project implements the Rijndael encryption algorithm (basis of AES standard), including core C implementation and Python test suite.

## File Structure

- `rijndael.h`/`rijndael.c`: Core algorithm implementation
  - Provides 128-bit encryption/decryption
  - Contains all low-level operations (SubBytes, ShiftRows, etc.)
  
- `main.c`: Demo program
  - Shows encryption/decryption flow
  - Includes simple test cases

- `test_rijndael.py`: Test suite
  - Unit tests for all core functions
  - Verifies Python and C implementation consistency
  - Includes edge case tests

- `Makefile`: Build configuration
  - Compiles dynamic library (`rijndael.so`)
  - Builds executable (`main`)

- `.github/workflows/build.yml`: CI configuration
  - Automatically runs tests
  - Verifies code correctness

## Usage

### Build and Run
```bash
make clean && make  # Build project
./main              # Run demo program
```

### Run Tests
```bash
# Requires Python environment
python -m pytest test_rijndael.py -v
```

### Continuous Integration
- Automatically on each push/pull request:
  1. Builds C library
  2. Runs all tests
  3. Reports results

## Development Notes

1. Core Algorithm:
   - 128-bit keys
   - Compliant with AES standard
   - Pure C implementation

2. Test Coverage:
   - All basic operations
   - Encryption/decryption roundtrip
   - Edge cases

3. Extensibility:
   - Can be extended to 192/256-bit
   - Modular design
