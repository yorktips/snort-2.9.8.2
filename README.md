A Shell Script that used to create a snort 2.9.8.2 build environment
chmod +x install.sh
./install.sh

// Parse IPv4 address (d.d.d.d).
func parseIPv4(s string) IP {
  var p [IPv4len]byte
  for i := 0; i < IPv4len; i++ {
    if len(s) == 0 {
      // Missing octets.
      return nil
    }
    if i > 0 {
      if s[0] != '.' {
        return nil
      }
      s = s[1:]
    }
    n, c, ok := dtoi(s)
    if !ok || n > 0xFF {
      return nil
    }
    s = s[c:]
    p[i] = byte(n)
  }
  if len(s) != 0 {
    return nil
  }
  return IPv4(p[0], p[1], p[2], p[3])
}	

func main(){
     dpi("127.0.0.1", "8.8.8.8","ffaafaaaffaa","bdbdbdbdbdbd")
     dpi("127.0.0.2", "8.8.8.8","ffaafaaaffab","bdbdbdbdbdbe")
     dpi("127.0.0.3", "8.8.8.8","ffaafaaaffac","bdbdbdbdbdbf")
}

func dpi(srcip string,dstip string, srcmac string, dstmac string) {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()
    // Send raw bytes over wire
    rawBytes := []byte{10, 20, 30}
    err = handle.WritePacketData(rawBytes)
    if err != nil {
        log.Fatal(err)
    }
    // Create a properly formed packet, just with
    // empty details. Should fill out MAC addresses,
    // IP addresses, etc.
    buffer = gopacket.NewSerializeBuffer()
    gopacket.SerializeLayers(buffer, options,
        &layers.Ethernet{},
        &layers.IPv4{},
        &layers.TCP{},
        gopacket.Payload(rawBytes),
    )
    outgoingPacket := buffer.Bytes()
    // Send our packet
    err = handle.WritePacketData(outgoingPacket)
    if err != nil {
        log.Fatal(err)
    }
    // This time lets fill out some information
    ipLayer := &layers.IPv4(parseIPv4(srcip),parseIPv4(dstip))
    ethernetLayer := &layers.Ethernet(ParseMAC(srcmac),ParseMAC(dstmac))
