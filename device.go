package device

import (
	"fmt"
	"github.com/d1937/gateway"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	"github.com/olekukonko/tablewriter"
	"github.com/phayes/freeport"
	"github.com/pkg/errors"
	"net"
	"os"
	"runtime"
	"time"
)

type NetInfo struct {
	Index        int              `json:"index,omitempty"`         //序号
	Name         string           `json:"name,omitempty"`          //net.interfaces 网卡名称
	DeviceName   string           `json:"device_name,omitempty"`   //pcap 网卡名称
	Ip           net.IP           `json:"ipaddr,omitempty"`        //本机IP
	HardwareAddr net.HardwareAddr `json:"hardware_addr,omitempty"` //本机mac
	Description  string           `json:"description,omitempty"`   //说明
}

type EthTable struct {
	Device      string           `json:"device,omitempty"`      //pcap 网卡名称
	Name        string           `json:"name,omitempty"`        //net.interfaces 网卡名称
	Description string           `json:"description,omitempty"` //说明
	SrcIp       net.IP           `json:"src_ip,omitempty"`      //本机IP
	DstIp       net.IP           `json:"dst_ip,omitempty"`      //网关IP
	SrcMac      net.HardwareAddr `json:"src_mac,omitempty"`     //本地网卡mac
	DstMac      net.HardwareAddr `json:"dst_mac,omitempty"`     //网关mac
	RawPort     int              `json:"raw_port,omitempty"`    //本地端口
	Handle      *pcap.Handle
}

func getRawPort() (int, error) {
	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return 0, err
	}
	return rawPort, nil
}

//getHwAddr 获取网关mac
func getHwAddr(ip net.IP, srcIP net.IP, SrcMac net.HardwareAddr, device string) (net.HardwareAddr, error) {

	// grab mac from ARP table if we have it cached
	macStr := arp.Search(ip.String())
	if macStr != "00:00:00:00:00:00" {
		if mac, err := net.ParseMAC(macStr); err == nil {
			return mac, nil
		}
	}

	handle, err := pcap.OpenLive(device, 65536, true, -1*time.Second)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	start := time.Now()

	// Prepare the layers to send for an ARP request.

	eth := &layers.Ethernet{
		SrcMAC:       SrcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         layers.ARPRequest,
		SourceHwAddress:   SrcMac,
		SourceProtAddress: srcIP,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    net.ParseIP(ip.String()).To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Send a single ARP request packet (we never retry a send, since this
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > 20*time.Second {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			a := arpLayer.(*layers.ARP)
			//fmt.Println(net.HardwareAddr(a.SourceHwAddress).String())
			if net.IP(a.SourceProtAddress).Equal(ip) {
				return net.HardwareAddr(a.SourceHwAddress), nil
			}
		}
	}
}

//获取网卡列表
func GetInterfaces() (map[string]*NetInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	data := make(map[string]*NetInfo, 0)
	for _, inter := range interfaces {
		address, err := inter.Addrs()
		if err != nil {
			continue
		}
		if len(address) == 2 {
			for _, addr := range address {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					return nil, err
				}
				if ipaddr := net.ParseIP(ip.String()); ipaddr != nil {
					if ipaddr.To4() != nil {
						if ipaddr.To4().String() == "127.0.0.1" {
							continue
						}
						data[ip.String()] = &NetInfo{
							Index:        inter.Index,
							Name:         inter.Name,
							Ip:           ip.To4(),
							HardwareAddr: inter.HardwareAddr,
						}
					}
				}
			}

		}

	}

	for _, device := range devices {
		if len(device.Addresses) == 2 {
			//fmt.Println(device.Addresses)
			//netaddr := device.Addresses[0]
			for _, address := range device.Addresses {
				if address.IP.To4() != nil {
					ipaddr := address.IP.String()
					if v, ok := data[ipaddr]; ok {
						v.DeviceName = device.Name
						v.Description = device.Description
						data[ipaddr] = v
					}
				}
			}

		}
	}

	return data, nil
}

//打印网卡列表
func PrintInterfaces() error {
	devices, err := GetInterfaces()
	if err != nil {
		return err
	}
	data := make([][]string, 0)
	for k, v := range devices {
		rows := []string{fmt.Sprintf("%d", v.Index), v.Name, k}
		data = append(data, rows)
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "网卡名称", "网卡IP"})
	for _, v := range data {
		table.Append(v)
	}
	table.Render() // Send output
	return nil
}

func GetIndexInterface(index int) (*NetInfo, error) {
	devices, err := GetInterfaces()
	if err != nil {
		return nil, err
	}
	for _, v := range devices {
		fmt.Println(v.Name)
		if v.Index == index {
			return v, err
		}
	}

	return nil, errors.New(fmt.Sprintf("id:%d,没有找到对应的网卡", index))
}

func GetDevice(index int) (*EthTable, error) {
	device, err := GetIndexInterface(index)
	if err != nil {
		return nil, err
	}

	var gwip net.IP

	if runtime.GOOS == "windows" {
		//获取网关IP
		gwip, err = gateway.DiscoverGateway(device.Ip.To4().String())

	} else {
		//获取网关IP
		gwip, err = gateway.DiscoverGateway(device.Name)

	}

	if err != nil {
		return nil, errors.Wrapf(err, "获取本机网关IP失败")
	}

	//获取网关mac
	dstMac, err := getHwAddr(gwip, device.Ip, device.HardwareAddr, device.DeviceName)
	if err != nil {
		return nil, errors.Wrapf(err, "初化网关mac失败")
	}

	//获取端口号
	rawPort, err := getRawPort()
	if err != nil {
		return nil, errors.Wrapf(err, "获取端口失败")
	}

	var (
		snapshotLen int32         = 1024
		promiscuous bool          = false
		timeout     time.Duration = 10 * time.Second
	)

	handle, err := pcap.OpenLive(device.DeviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		return nil, err
	}

	eth := &EthTable{
		Device:      device.DeviceName,
		Name:        device.Name,
		Description: device.Description,
		SrcIp:       device.Ip,
		DstIp:       gwip,
		SrcMac:      device.HardwareAddr,
		DstMac:      dstMac,
		RawPort:     rawPort,
		Handle:      handle,
	}

	return eth, nil
}

/*
AutoGetDevice
1. 获取本机ip和mac
2. 获取网关IP
3. 获取网关mac
*/

func AutoGetDevice() (*EthTable, error) {
	//获取本机IP
	localIp, err := gateway.DiscoverInterface("")
	if err != nil {
		return nil, errors.Wrapf(err, "获取本机网卡IP失败")
	}
	//获取网关IP
	gateayIp, err := gateway.DiscoverGateway("")
	if err != nil {
		return nil, errors.Wrapf(err, "获取本机网关IP失败")
	}

	//获取网卡列表
	devices, err := GetInterfaces()
	if err != nil {
		return nil, errors.Wrapf(err, "获取网卡列表失败")
	}
	var device *NetInfo
	if d, ok := devices[localIp.String()]; ok {
		device = d
	} else {
		return nil, errors.Wrapf(err, "初化网卡接口失败")
	}

	//获取网关mac
	dstMac, err := getHwAddr(gateayIp, device.Ip, device.HardwareAddr, device.DeviceName)
	if err != nil {
		return nil, errors.Wrapf(err, "初化网关mac失败")
	}

	//获取端口号
	rawPort, err := getRawPort()
	if err != nil {
		return nil, errors.Wrapf(err, "获取端口失败")
	}

	var (
		snapshotLen int32         = 1024
		promiscuous bool          = false
		timeout     time.Duration = 10 * time.Second
	)

	handle, err := pcap.OpenLive(device.DeviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		return nil, err
	}

	eth := &EthTable{
		Device:      device.DeviceName,
		Name:        device.Name,
		Description: device.Description,
		SrcIp:       localIp,
		DstIp:       gateayIp,
		SrcMac:      device.HardwareAddr,
		DstMac:      dstMac,
		RawPort:     rawPort,
		Handle:      handle,
	}

	return eth, nil

}
