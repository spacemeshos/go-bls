# Spacemesh go-bls lib POC

This is an experimental eraly POC. Be warend, dragons ahead.

## Building

This is all a temp big hack that should be automated. For now...


```
git clone https://github.com/spacemeshos/go-bls
cd go-bls
mkdir external
cd external
git clone https://github.com/herumi/mcl.git
git clone https://github.com/herumi/bls.git
cd mcl
make test-go
cd ..
cd bls
make test-go
cd ..
go build
```

## Testing
```
go test ./tests/. -v
```

## Examples
```
cd examples
export DYLD_LIBRARY_PATH=[YR-GO-PATH]/src/github.com/spacemeshos/go-bls/external/bls/lib
go run main.go

```

## TODO
- [ ] investigate prng injection from go
