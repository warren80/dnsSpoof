require 'rubygems'
require 'packetfu'

include PacketFu
class Sniff
	def	intialize()

	end
	
	def start
		filter = "udp and port 53"
		cap = Capture.new(:iface => $iface, :start => true, :promisc => true, \
						  :filter => filter, :save=>true)
		cap.stream.each do |p|
			@pkt = Packet.parse(p)
			#check if packet type is query
			if @pkt.payload[2]  == 1 && @pkt.payload[3]  == 0
				domainName = getDomainName(@pkt.payload[12..-1])
				if domainName.nil?
					puts "domainName nil"
					next
				end
				puts "DNS request recieved from: #{domainName}"
#				transactionId = pkt.payload[0,2]
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

	def genDnsResponce(transactionId, domainName, dst_port, ip_saddr, eth_saddr)
		
	end

end

def test
	sniff = Sniff.new
	sniff.start
end

test
