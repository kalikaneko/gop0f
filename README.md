# Gop0f - Client library for p0f passive fingerprinting

## Installing
```
go get github.com/kalikaneko/gop0f
```

## Using

Using the library in your service:
```
import (
  "github.com/kalikaneko/gop0f"
  "net"
)

p0fclient, err := gop0f.New("/var/run/p0f.socket")
if err != nil {
  panic(err)
}
resp, err := p0fclient.Query(net.ParseIP("127.0.0.1"))
if err != nil {
  panic(err)
}
```

Using the included cli tool:
```
$ p0f-cli -q 127.0.0.1
```

## Further reading
Read more about [p0f](http://lcamtuf.coredump.cx/p0f3/) by Michal Zalewski
