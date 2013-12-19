package stun

import (
	"crypto/rand"
	"net"
)

const (
	Request byte = iota
	Indication
	Success
	Error
)

const (
	_ uint16 = iota
	Binding
	SharedSecret
)

const (
	_ uint16 = iota
	MappedAddressCode
	ResponseAddressCode
	ChangeAddressCode
	SourceAddressCode
	ChangedAddressCode
	UsernameCode
	PasswordCode
	MessageIntegrityCode
	ErrorCode
	UnknownAttributesCode
	ReflectedFromCode
)

type StunMessage struct {
	// 14 bit message type: 12 bit Method + 2 bit Class encoding
	//	+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
	//	|M |M |M|M|M|C|M|M|M|C|M|M|M|M|
	//	|11|10|9|8|7|1|6|5|4|0|3|2|1|0|
	//	+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
	Method uint16
	Class byte

	// Message Length: 16 bits
	Length int

	// Magic Cookie: always 0x2112A442 in network order
	Cookie []byte

	// Transaction ID: Random 96 bits
	TransID []byte

	Attrs []StunAttribute
}

// Generates new StunHeader with random TransactionID
func NewMessage() StunMessage {
	header := StunMessage{}
	header.Cookie = make([]byte,4)
	header.Cookie[0] = 0x21
	header.Cookie[1] = 0x12
	header.Cookie[2] = 0xa4
	header.Cookie[3] = 0x42

	header.TransID = make([]byte, 12)
	_,err := rand.Read(header.TransID)
	if err != nil {
		panic(err)
	}

	header.Length = 0

	header.Attrs = make([]StunAttribute,0,128) // shouldn't need more than this. too lazy to math

	return header
}

// Encode the method and class as a type in network order
func ToType(method uint16, class byte) []byte {
	var m0,m1 byte
	m0 = byte(method >> 8)
	m1 = byte(method)
	var t0,t1 byte
	t1 = (m1 & 0x0f) | ((class & 0x01) << 4) | ((m1 << 1) & 0xe0)
	t0 = ((class & 0x02) >> 1) | ((m1 & 0xef) >> 6) | ((m0 & 0x3f) << 2)

	return []byte{t0,t1}
}

func (h StunMessage) Bytes() []byte {
	b := make([]byte, 20 + h.Length)
	Type := ToType(h.Method,h.Class)
	var i,j,k,l int
	for i = 0; i < 2; i++ {
		b[i] = Type[i]
	}
	// convert length to 2 bytes
	length := make([]byte,2)
	length[0] = byte(uint16(h.Length) >> 8)
	length[1] = byte(uint16(h.Length))
	for j = i; j < i + 2; j++ {
		b[j] = length[j - i]
	}
	for k = j; k < j + 4; k++ {
		b[k] = h.Cookie[k - j]
	}
	for l = k; l < k + 12; l++ {
		b[l] = h.TransID[l - k]
	}
	for _,v := range h.Attrs {
		for _,q := range v.Bytes() {
			b[l] = q
			l++
		}
	}
	return b
}

func (m *StunMessage) AddAttribute(attr StunAttribute) {
	m.Length += attr.Length + 4
	l := len(m.Attrs)
	if l + 1 > cap(m.Attrs) {
		newAttrs := make([]StunAttribute, l + 128)
		copy(newAttrs,m.Attrs)
		m.Attrs = newAttrs
	}
	m.Attrs = m.Attrs[0:1 + l]
	m.Attrs[l] = attr
}


type StunAttribute struct {
	// 16 bit Type
	Type uint16

	// 16 bit length
	Length int

	// Variable Length Attribute
	Attr AttributeValue
}

func (a StunAttribute) Bytes() []byte {
	bytes := make([]byte,4 + len(a.Attr.Bytes()))
	bytes[0] = byte(a.Type >> 8)
	bytes[1] = byte(a.Type)
	bytes[2] = byte(uint16(a.Length) >> 8)
	bytes[3] = byte(uint16(a.Length))
	for i,v := range a.Attr.Bytes() {
		bytes[4 + i] = v
	}
	return bytes
}

type AttributeValue interface {
	Bytes() []byte
}

type MappedAddressAttr struct {
	Family byte
	Port int
	Address net.IP
}

func (m MappedAddressAttr) Bytes() []byte {
	var bytes []byte
	var ip net.IP
	if m.Family == 0x01 {
		bytes = make([]byte,8)
		ip = m.Address.To4()
	} else {
		bytes = make([]byte,20)
		ip = m.Address.To16()
	}

	bytes[0] = 0x00
	bytes[1] = m.Family
	port16 := uint16(m.Port)
	bytes[2] = byte(port16 >> 8)
	bytes[3] = byte(port16)

	for i,v := range ip {
		bytes[4+i] = v
	}

	return bytes
}


func MappedAddress(address string,port int) StunAttribute {
	ip := net.ParseIP(address)
	ip4 := ip.To4()
	ip6 := ip.To16()

	var family byte

	if ip4 == nil {
		if ip6 == nil {
			panic("Failed to parse IP!")
		}
		ip = ip6
		family = 0x02
	} else {
		ip = ip4
		family = 0x01
	}

	ma :=  MappedAddressAttr{family,port,ip}
	return StunAttribute{0x0001, len(ma.Bytes()), ma}
}

type RawAttr struct {
	Data []byte
}

func (r RawAttr) Bytes() []byte {
	return r.Data
}

func ParseAttr(bytes []byte) (StunAttribute,int) {
	typeBytes := bytes[0:2]
	lenBytes := bytes[2:4]
	var typeVal uint16
	typeVal = (uint16(typeBytes[0]) << 8) | uint16(typeBytes[1])
	var lenVal int
	lenVal = int((uint16(lenBytes[0]) << 8) | uint16(lenBytes[1]))
	attr := StunAttribute{Type: typeVal,Length: lenVal}
	if typeVal == 0x0001 {
		println("Found an addr message!")
		ma := MappedAddressAttr{}
		ma.Family = bytes[5]
		ma.Port = int((uint16(bytes[6]) << 8) | uint16(bytes[7]))
		if ma.Family == 0x01 {
			ma.Address = net.IPv4(bytes[8],bytes[9],bytes[10],bytes[11])
		} else {
			copy(ma.Address,bytes[8:lenVal+4])
		}
		attr.Attr = ma
	} else {
		data := make([]byte,lenVal)
		copy(data,bytes[4:lenVal+4])
		attr.Attr = RawAttr{data}
	}

	return attr,4 + lenVal
}

func ParseMessage(bytes []byte) StunMessage {
	mes := StunMessage{}
	//typeBytes := bytes[0:2] // screw this for now
	lenBytes := bytes[2:4]
	//var typeVal uint16
	mes.Length = int((uint16(lenBytes[0]) << 8) | uint16(lenBytes[1]))
	mes.Cookie = make([]byte,4)
	mes.TransID = make([]byte,12)
	copy(mes.Cookie,bytes[4:8])
	copy(mes.TransID,bytes[8:20])

	attrData := bytes[20:]
	attrLen := len(attrData)
	for i := 0; i < attrLen; {
		attr,m := ParseAttr(attrData[i:])
		i += m
		mes.AddAttribute(attr)
	}
	return mes
}

func SendMessage(m StunMessage, local, remote string) StunMessage {
	laddr,err := net.ResolveUDPAddr("udp",local)
	if err != nil {
		panic(err)
	}
	raddr,err := net.ResolveUDPAddr("udp",remote)
	if err != nil {
		panic(err)
	}

	conn,err := net.DialUDP("udp",laddr,raddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_,err = conn.Write(m.Bytes())
	if err != nil {
		panic(err)
	}

	resp := make([]byte,1024)
	n,err := conn.Read(resp)
	if err != nil {
		panic(err)
	}

	realResp := make([]byte,n)
	copy(realResp,resp)

	mes := ParseMessage(realResp)

	return mes
}
