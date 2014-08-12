sgraph
======

Go SGraph API

## Installation

### Make sure your $GOPATH is set
If you haven't already, make the directory you want your third-party/custom Go libs in:
```sh
mkdir ~/go
```

Then set your $GOPATH environment variable and add the `bin` folder to your $PATH. Do this by adding these lines to your `.bashrc`:
```sh
export GOPATH=$HOME/go
export PATH="$PATH:$GOPATH/bin"
```

### go get it
`go get github.office.opendns.com/skyler/sgraph`

## Docs
To view the docs, just start a local godoc server:

```
godoc -http=:6060
```

and open `localhost:6060` in your web browser. The docs will be under `github.office.opendns.com/skyler/sgraph`.
