# Vyper Structure aware fuzzing

## Install dependencies
Before installing the main, the necessary Python libs are required to install:  
`cmake` >= 3.20  
`python3.10`  
Once the requirements above are satisfied, run
```bash
./install.sh
```

## TO-DO list

- [ ] Resolve all TO-DO comments
- [ ] Check all cases in conversions (especially in bytes-like types - Bytes, String)
- [ ] Divide coversion in two separate parts: with literals and with constants
- [ ] Declare String type with arbitrary length param, but restrict actual len of randomly generated string
- [ ] Add possibility in converter and proto for generating signed ints
- [ ] Code refactoring to avoid code duplication
- [ ] Add missing built-ins
- [ ] Add reference types 