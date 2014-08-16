import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;


public class watchdog_main {
	
	public static boolean exitloop=false;
	
	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
  
        /*************************************************************************** 
         * First get a list of devices on this system 
         **************************************************************************/  
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }  
  
        System.out.println("Network devices found:");  
  
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }  
  
        PcapIf device = alldevs.get(0); // We know we have atleast 1 device  
        System.out  
            .printf("\nChoosing '%s' on your behalf:\n",  
                (device.getDescription() != null) ? device.getDescription()  
                    : device.getName());  
  
        /*************************************************************************** 
         * Second we open up the selected device 
         **************************************************************************/  
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        final Pcap pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  
  
        /*************************************************************************** 
         * Fourth we enter the loop and tell it to capture 10 packets. The loop 
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which 
         * is needed by JScanner. The scanner scans the packet buffer and decodes 
         * the headers. The mapping is done automatically, although a variation on 
         * the loop method exists that allows the programmer to sepecify exactly 
         * which protocol ID to use as the data link type for this pcap interface. 
         **************************************************************************/  
        
        //thread to listen for exit
        final listener_exit listener_exit_thread=new listener_exit();
        listener_exit_thread.start();
        
        pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Object>() {  
        	  
            /** 
             * We purposely define and allocate our working headers (accessor) 
             * outside the dispatch function and thus the libpcap loop, as this type 
             * of object is reusable and it would be a very big waste of time and 
             * resources to allocate it per every dispatch of a packet. We mark it 
             * final since we do not plan on allocating any other instances of them. 
             */  
            final Tcp tcp = new Tcp();  
            final PcapPacket packet = new PcapPacket(JMemory.POINTER);  
            final Ip4 ip = new Ip4();  
            
            /*main work here. We want to scan each incoming packet, and check the process its attached to.
             * If its steam, check if its a tcp/ucp packet, and is leaving the local ip.
             * If so, add it to a global buffer of ips along with its capture time. Its a Dks2 user ip.
             * also, use convo_id*/
            public void nextPacket(PcapHeader header, JBuffer buffer, Object user) {  
            	packet.peerAndScan(Ethernet.ID, header, buffer);  
            	
            	HashMap<String,String> packetinfo = new HashMap<String,String>(4);
            	
            	packetinfo.put("time",new Date(packet.getCaptureHeader().timestampInMillis()).toString());
            	
            	if (packet.hasHeader(ip) && packet.hasHeader(tcp)){
            		packetinfo.put("from ip",FormatUtils.ip(ip.source()));
            		packetinfo.put("dest ip",FormatUtils.ip(ip.destination()));
            		packetinfo.put("from port",String.valueOf(tcp.source()));
            		packetinfo.put("dest port",String.valueOf(tcp.destination()));
            	}
            	
            	for(String info:packetinfo.keySet()){
            		System.out.print(info+":"+packetinfo.get(info)+"   ");
            	}
            	System.out.println("");
            	
            	//to exit loop
            	if (exitloop) {
            		System.out.println("stopping");
            		listener_exit_thread.listening=false;
            		pcap.breakloop();
            	}
            }
  
        }, errbuf);  
  
        /*************************************************************************** 
         * Last thing to do is close the pcap handle 
         **************************************************************************/  
        pcap.close(); 

	}

}
