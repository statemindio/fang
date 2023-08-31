# Vyper Structure aware fuzzing

## TO-DO list

- [ ] Resolve all TO-DO comments
- [ ] Check all cases in conversions (especially in bytes-like types - Bytes, String)
- [ ] Divide coversion in two separate parts: with literals and with constants
- [ ] Declare String type with arbitrary length param, but restrict actual len of randomly generated string
- [ ] Add possibility in converter and proto for generating signed ints
- [ ] Code refactoring to avoid code duplication
- [ ] Add missing built-ins
- [ ] Add reference types 