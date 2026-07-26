GOOS=darwin     GOARCH=amd64    go build -ldflags '-s' -o bin/wireguard-darwin-amd64       *.go
GOOS=darwin     GOARCH=arm64    go build -ldflags '-s' -o bin/wireguard-darwin-arm64       *.go
GOOS=linux      GOARCH=386      go build -ldflags '-s' -o bin/wireguard-linux-386          *.go
GOOS=linux      GOARCH=amd64    go build -ldflags '-s' -o bin/wireguard-linux-amd64        *.go
GOOS=linux      GOARCH=arm      go build -ldflags '-s' -o bin/wireguard-linux-arm          *.go
GOOS=linux      GOARCH=arm64    go build -ldflags '-s' -o bin/wireguard-linux-arm64        *.go
GOOS=windows    GOARCH=386      go build -ldflags '-s' -o bin/wireguard-windows-386.exe    *.go
GOOS=windows    GOARCH=amd64    go build -ldflags '-s' -o bin/wireguard-windows-amd64.exe  *.go