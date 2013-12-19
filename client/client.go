package main

import (
	"net"
	"fmt"
	"github.com/Pursuit92/stun"
)


func PrintHeader(bytes []byte) {
	fmt.Println("Type, Length:")
	for i := 0; i < 4; i++ {
		fmt.Printf("%0.8b",bytes[i])
		fmt.Printf(" ")
	}
	fmt.Println("\nCookie:")
	for i := 4; i < 8; i++ {
		fmt.Printf("%0.8b",bytes[i])
		fmt.Printf(" ")
	}
	fmt.Println("\nTransID:")
	for i := 8; i < 12; i++ {
		fmt.Printf("%0.8b",bytes[i])
		fmt.Printf(" ")
	}
	fmt.Println()
	for i := 12; i < 16; i++ {
		fmt.Printf("%0.8b",bytes[i])
		fmt.Printf(" ")
	}
	fmt.Println()
	for i := 16; i < 20; i++ {
		fmt.Printf("%0.8b",bytes[i])
		fmt.Printf(" ")
	}
	fmt.Println()
}

func PrintBytes(bytes []byte) {
	fmt.Printf("%d Bytes:\n",len(bytes))
	for i,v := range bytes {
		fmt.Printf("%0.8b",v)
		if i % 4 == 3 {
			fmt.Println()
		} else {
			fmt.Print(" ")
		}
	}
}

func main() {

	h := stun.NewMessage()
	h.Class = stun.Request
	h.Method = stun.Binding
	ma := stun.MappedAddress("0.0.0.0",1234)
	h.AddAttribute(ma)

	PrintHeader(h.Bytes())

	fmt.Println()

	PrintBytes(h.Bytes())

	laddr,e := net.ResolveUDPAddr("udp","0.0.0.0:1234")
	if e != nil {
		panic(e)
	}
	raddr,e := net.ResolveUDPAddr("udp","stun.stunprotocol.org:3478")
	if e != nil {
		panic(e)
	}
	conn,e := net.DialUDP("udp",laddr,raddr)

	if e != nil {
		panic(e)
	}
	defer conn.Close()
	resp := make([]byte,1024)
	_,e = conn.Write(h.Bytes())
	if e != nil {
		panic(e)
	}
	n,e := conn.Read(resp)
	if e != nil {
		panic(e)
	}
	fmt.Println()
	fmt.Printf("Read %d bytes:\n",n)

	realResp := make([]byte,n)
	copy(realResp,resp)

	mes := stun.ParseMessage(realResp)

	fmt.Println()
	PrintBytes(mes.Bytes())

	PrintHeader(mes.Bytes())

	for i,v := range mes.Attrs {
		ipMes,ok := v.Attr.(stun.MappedAddressAttr)
		if ok {
			fmt.Printf("IP: %v, Port: %v\n",ipMes.Address, ipMes.Port)
		} else {
			fmt.Printf("Attr %d has length %d and type %0.4x\n",i,v.Length,v.Type)
		}
	}

}

