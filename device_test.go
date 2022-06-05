package device

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestGetInterFaceInfo(t *testing.T) {

	PrintInterfaces()
}

func TestAutoGetDevice(t *testing.T) {
	eth, err := AutoGetDevice()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(eth)
	data, err := json.MarshalIndent(eth, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(data))

}

func TestGetIndexInterface(t *testing.T) {
	inter, err := GetIndexInterface(100)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(inter.Ip, inter.DeviceName)
}

func TestGetDevice(t *testing.T) {
	device, err := GetDevice(19)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(device)
}

func Test_getRawPort(t *testing.T) {
	port, err := getRawPort()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(port)
}
