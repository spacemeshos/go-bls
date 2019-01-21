# Spacemesh go-bls lib POC

This is an experimental early POC. Be warned, dragons ahead...

## Building

Native requirements: gcc, libgmp-dev libssl-dev

```
git clone https://github.com/spacemeshos/go-bls
cd go-bls
git submodule init
git submodule update
cd external/mcl
make test
make test-go
cd ..
cd bls
make test
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

