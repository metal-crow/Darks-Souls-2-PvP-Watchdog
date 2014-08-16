import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
  
        
        //pre-build library for networked processes and process names
    	//TODO i dont know if theres a better way/library of doing this, so for know im just going to run a cmd command and parse the text
    	StringBuffer networked_processessb=new StringBuffer();
    	StringBuffer system_processessb=new StringBuffer();
		try {
			//get list of all networked processes
			Process p = Runtime.getRuntime().exec("netstat -aon");
			BufferedReader commandoutput = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line = null;  
            while ((line = commandoutput.readLine()) != null) {  
            	networked_processessb.append(line.trim()+"\n");
            }
            //get list of process names with their Pid
            p = Runtime.getRuntime().exec("tasklist");
            commandoutput = new BufferedReader(new InputStreamReader(p.getInputStream()));
            line = null;  
            while ((line = commandoutput.readLine()) != null) {  
            	system_processessb.append(line.trim()+"\n");
            }
            
		} catch (IOException e) {
			System.err.println("Problem opening cmd");
			e.printStackTrace();
		}
		final String[] networked_processes=networked_processessb.toString().split("\n");
		final String[] system_processes=system_processessb.toString().split("\n");
        
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
            	
            	String[] packetinfo = new String[5];
            	
            	packetinfo[0]=new Date(packet.getCaptureHeader().timestampInMillis()).toString();
            	
            	//Check if the packet has tcp and ip headers. If so, get its ports and ips
            	if (packet.hasHeader(ip) && packet.hasHeader(tcp)){
            		//packetinfodebug.put("from ip",FormatUtils.ip(ip.source()));
            		//packetinfodebug.put("dest ip",FormatUtils.ip(ip.destination()));
            		//packetinfodebug.put("from port",String.valueOf(tcp.source()));
            		//packetinfodebug.put("dest port",String.valueOf(tcp.destination()));
            		
            		packetinfo[1]=FormatUtils.ip(ip.source());
            		packetinfo[2]=String.valueOf(tcp.source());
            		packetinfo[3]=FormatUtils.ip(ip.destination());
            		packetinfo[4]=String.valueOf(tcp.destination());
            	}
            	
            	//we sucesfully got ips and ports
            	if(packetinfo[1]!=null && packetinfo[2]!=null && packetinfo[3]!=null && packetinfo[4]!=null){
	            	//next we check the list of networked processes and get the one that has connections matching all 4 variables from the header
	            	//checking processes is expensive, so do it once on program start, then consult the stored list
	            	
            		String PiD=null;
            		String processname=null;
            		
	            	for(String networked_process:networked_processes){
						if(networked_process.contains(packetinfo[1]+":"+packetinfo[2]) && networked_process.contains(packetinfo[3]+":"+packetinfo[4])){
							//we found the process for this packet, get its pid
							String[] process=networked_process.split("\\s+");
							PiD=process[process.length-1];
							break;
						}
	            	}
	            	
	            	//we only got the PID, so query the OS using the process ID and get the process name 
	            	//if this process is steam, then we add the destination ip address (if its leaving local ip) to list of Dks2 player ips
	            	for(String process:system_processes){
	            		if(process.contains(PiD)){
	            			int endposition = 0;
	            			Pattern p = Pattern.compile("\\s+");
	            			Matcher m = p.matcher(process);
	            			if (m.find()) {endposition = m.start();}
	            			
	            			processname=process.substring(0,endposition);
							break;
	            		}
	            	}
	            	
	            	System.out.println("found ip adress "+packetinfo[3]+" from process "+processname);
            	}
            	
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
