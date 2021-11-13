package gop0f

import (
	//	"bytes"
	//	"encoding/binary"
	//	"encoding/hex"
	"bytes"
	"fmt"
	"io"
	"net"
)

const (
	P0F_STATUS_BADQUERY = 0x00
	P0F_STATUS_OK       = 0x10
	P0F_STATUS_NOMATCH  = 0x20
	P0F_ADDR_IPV4       = 0x04
	P0F_ADDR_IPV6       = 0x06
	P0F_STR_MAX         = 31
	P0F_MATCH_FUZZY     = 0x01
	P0F_MATCH_GENERIC   = 0x02
)

var (
	P0F_QUERY_MAGIC = []byte{0x01, 0x46, 0x30, 0x50} // 0x50304601
	P0F_RESP_MAGIC  = []byte{0x02, 0x46, 0x30, 0x50} //0x50304602
)

type GoP0f struct {
	conn   net.Conn
	socket string
}

type P0fResponse struct {
	Magic      uint32                // Must be P0F_RESP_MAGIC
	Status     uint32                // P0F_STATUS_*
	FirstSeen  uint32                // First seen (unix time)
	LastSeen   uint32                // Last seen (unix time)
	TotalCount uint32                // Total connections seen
	UptimeMin  uint32                // Last uptime (minutes)
	UpModDays  uint32                // Uptime modulo (days)
	LastNat    uint32                // NAT / LB last detected (unix time)
	LastChg    uint32                // OS chg last detected (unix time)
	Distance   uint32                // System distance
	BadSw      byte                  // Host is lying about U-A / Server
	OsMatchQ   byte                  // Match quality
	OsName     [P0F_STR_MAX + 1]byte // Name of detected OS
	OsFlavor   [P0F_STR_MAX + 1]byte // Flavor of detected OS
	HttpName   [P0F_STR_MAX + 1]byte // Name of detected HTTP app
	HttpFlavor [P0F_STR_MAX + 1]byte // Flavor of detected HTTP app
	LinkType   [P0F_STR_MAX + 1]byte // Link type
	Language   [P0F_STR_MAX + 1]byte // Language
}

func New(sock string) (p0f *GoP0f, err error) {
	p0f = &GoP0f{
		socket: sock,
	}
	p0f.conn, err = net.Dial("unix", p0f.socket)
	if err != nil {
		return
	}
	return
}

func (p0f *GoP0f) Close() {
	p0f.conn.Close()
}

func (p0f *GoP0f) Query(addr net.IP) (resp P0fResponse, err error) {
	// Query = 21 bytes
	// Magic + 4 (ipv4) + ipaddr bytes + padding
	ip := []byte(addr)[len(addr)-4 : len(addr)]
	query := P0F_QUERY_MAGIC
	query = append(query[:], []byte{4}...)
	query = append(query[:], ip...)
	query = append(query[:], bytes.Repeat([]byte{0}, 12)...)
	fmt.Println(query)

	_, err = p0f.conn.Write(query)
	if err != nil {
		return
	}

	r := P0fResponse{}

	data := make([]byte, 1024)
	zeroes := 0
	n, err := p0f.conn.Read(data[:])
	fmt.Printf("Got %d bytes\n", n)
	if err != nil {
		if err != io.EOF {
			fmt.Println(err)
			return r, err
		}
	}
	data = data[:n]
	fmt.Println(data)
	for _, b := range data {
		if b != 0 {
			//fmt.Printf("%v\n", b)
		} else {
			zeroes++
		}
	}
	return r, nil
}
