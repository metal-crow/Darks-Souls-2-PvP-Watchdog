import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
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
  
        
        //get list of all networked processes
    	//TODO i dont know if theres a better way/library of doing this, so for know im just going to run a cmd command and parse the text
    	StringBuffer networked_processessb=new StringBuffer();
		try {
			Process p = Runtime.getRuntime().exec("netstat -aon");
			BufferedReader commandoutput = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line = null;  
            while ((line = commandoutput.readLine()) != null) {  
            	if(line.length()>0){
            		networked_processessb.append(line.trim()+"\n");
            	}
            }  
		} catch (IOException e) {
			System.err.println("Problem opening cmd");
			e.printStackTrace();
		}
		final String[] networked_processes=networked_processessb.toString().split("\n");
        
        /*************************************************************************** 
         * We enter the loop and tell it to capture packets. The loop 
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which 
         * is needed by JScanner. The scanner scans the packet buffer and decodes 
         * the headers. The mapping is done automatically, although a variation on 
         * the loop method exists that allows the programmer to sepecify exactly 
         * which protocol ID to use as the data link type for this pcap interface. 
         **************************************************************************/  
        
        //thread to listen for commands from user
        final commands_listener commands_listener_thread=new commands_listener();
        commands_listener_thread.start();
        
        //TODO polling rate is really high, eats up cpu. Lower somehow.
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
            
            //main work here. We want to scan each incoming packet, and check the process its attached to.
            public void nextPacket(PcapHeader header, JBuffer buffer, Object user) {  
            	packet.peerAndScan(Ethernet.ID, header, buffer);  
            	
            	HashMap<String,String> packetinfodebug = new HashMap<String,String>(4);
            	String[] packetinfo = new String[2];
            	
            	packetinfodebug.put("time",new Date(packet.getCaptureHeader().timestampInMillis()).toString());
            	
            	//Check if the packet has tcp and ip headers. If so, get its ports and ips
            	if (packet.hasHeader(ip) && packet.hasHeader(tcp)){
            		packetinfodebug.put("from ip",FormatUtils.ip(ip.source()));
            		packetinfodebug.put("dest ip",FormatUtils.ip(ip.destination()));
            		packetinfodebug.put("from port",String.valueOf(tcp.source()));
            		packetinfodebug.put("dest port",String.valueOf(tcp.destination()));
            		
            		packetinfo[0]=FormatUtils.ip(ip.source())+":"+String.valueOf(tcp.source());
            			System.out.println(packetinfo[0]);
            		packetinfo[1]=FormatUtils.ip(ip.destination())+":"+String.valueOf(tcp.destination());
            			System.out.println(packetinfo[1]);
            	}
            	
            	/*for(String info:packetinfodebug.keySet()){
            		System.out.print(info+":"+packetinfodebug.get(info)+"   ");
            	}
            	System.out.println("");*/
            	
            	//next we check the list of networked processes and get the one that has connections matching all 4 variables from the header
            	//checking processes is EXTREMELY expensive, so do it once on program start, then consult the stored list
            	
            	for(String networked_process:networked_processes){
					if(networked_process.contains(packetinfo[0]) && networked_process.contains(packetinfo[1])){
						//we found the process for this packet, get its pid
						System.out.println(networked_process);
					}
            	}
            	
            	//we only got the PID, so query the OS using the process ID and get the process name 
            	//if this process is steam, then we add the destination ip address (if its leaving local ip) to list of Dks2 player ips
            	
            	
            	//to exit loop
            	if (exitloop) {
            		System.out.println("stopping");
            		commands_listener_thread.listening=false;
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
