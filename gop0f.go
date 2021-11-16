package gop0f

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
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

type p0fResponse struct {
	Magic      uint32                // Must be P0F_RESP_MAGIC
	Status     uint32                // P0F_STATUS_*
	FirstSeen  uint32                // First seen (unix time)
	LastSeen   uint32                // Last seen (unix time)
	TotalCount uint32                // Total connections seen
	UptimeMin  uint32                // Last uptime (minutes)
	UpModDays  uint32                // Uptime modulo (days)
	LastNat    uint32                // NAT / LB last detected (unix time)
	LastChg    uint32                // OS chg last detected (unix time)
	Distance   uint16                // System distance
	BadSw      byte                  // Host is lying about U-A / Server
	OsMatchQ   byte                  // Match quality
	OsName     [P0F_STR_MAX + 1]byte // Name of detected OS
	OsFlavor   [P0F_STR_MAX + 1]byte // Flavor of detected OS
	HttpName   [P0F_STR_MAX + 1]byte // Name of detected HTTP app
	HttpFlavor [P0F_STR_MAX + 1]byte // Flavor of detected HTTP app
	LinkType   [P0F_STR_MAX + 1]byte // Link type
	Language   [P0F_STR_MAX + 1]byte // Language
}

type OSMatchQuality int

const (
	Normal OSMatchQuality = 0 + iota
	Fuzzy
	Signature
	FuzzySignature
)

type IPInfo struct {
	OsMatchQ   OSMatchQuality // Match quality
	BadSw      int            // Host is lying about U-A / Server
	Distance   uint16         // System distance
	OsName     string         // Name of detected OS
	OsFlavor   string         // Flavor of detected OS
	HttpName   string         // Name of detected HTTP app
	HttpFlavor string         // Flavor of detected HTTP app
	LinkType   string         // Link type
	Language   string         // Language
}

func NewInfo(r p0fResponse) (info IPInfo, err error) {
	// TODO check magic
	if r.Status != P0F_STATUS_OK {
		e := "UNKNOWNERR"
		switch r.Status {
		case P0F_STATUS_NOMATCH:
			e = "NOMATCH"
		case P0F_STATUS_BADQUERY:
			e = "BADQUERY"
		}
		return IPInfo{}, errors.New(e)

	}
	i := IPInfo{
		OsMatchQ:   OSMatchQuality(r.OsMatchQ),
		BadSw:      int(r.BadSw),
		Distance:   r.Distance,
		OsName:     toString(r.OsName),
		OsFlavor:   toString(r.OsFlavor),
		HttpName:   toString(r.HttpName),
		HttpFlavor: toString(r.HttpFlavor),
		LinkType:   toString(r.LinkType),
		Language:   toString(r.Language),
	}
	return i, nil
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

func (p0f *GoP0f) Query(addr net.IP) (info IPInfo, err error) {
	if len(addr) < 4 {
		return IPInfo{}, nil
	}
	// Query = 21 bytes
	// Magic + 4 (ipv4) + ipaddr bytes + padding
	ip := []byte(addr)[len(addr)-4 : len(addr)]
	query := P0F_QUERY_MAGIC
	query = append(query[:], []byte{P0F_ADDR_IPV4}...)
	query = append(query[:], ip...)
	query = append(query[:], bytes.Repeat([]byte{0}, 12)...)

	_, err = p0f.conn.Write(query)
	if err != nil {
		return
	}

	r := p0fResponse{}
	data := make([]byte, 1024)
	n, err := p0f.conn.Read(data[:])
	if err != nil {
		if err != io.EOF {
			fmt.Println(err)
			return IPInfo{}, err
		}
	}
	data = data[:n]
	buf := bytes.NewReader(data)
	err = binary.Read(buf, binary.LittleEndian, &r)
	if err != nil {
		log.Fatalf("binary.Read failed: %v", err)
	}
	info, err = NewInfo(r)
	if err != nil {
		fmt.Println("Error: " + err.Error())
	}
	return info, nil
}

func toString(ba [32]byte) string {
	n := bytes.IndexByte(ba[:], 0)
	return string(ba[:n])
}
