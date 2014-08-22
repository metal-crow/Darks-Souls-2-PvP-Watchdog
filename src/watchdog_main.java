import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.Arrays;
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
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;


public class watchdog_main {
	
	public static boolean exitloop=false;
	public static boolean toblock=false;
	public static commands_listener commands_listener_thread=new commands_listener();
	
	private static ArrayList<String[]> recent_Dks2_ips = new ArrayList<String[]>();
	private static ArrayList<String> blocked_Dks2_ips = new ArrayList<String>();
	
	private static Runtime rt=Runtime.getRuntime();
	private static BufferedReader commandoutput;
	
	public static void main(String[] args) throws IOException {
		
		read_block_list();
		
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
  
        
        //pre-build library for process names
    	//TODO i dont know if theres a better way/library of doing this, so for know im just going to run a cmd command and parse the text
    	StringBuffer system_processessb=new StringBuffer();
		try {
            //get list of process names with their Pid
            Process p = rt.exec("tasklist");
            commandoutput = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = null;  
            while ((line = commandoutput.readLine()) != null) {  
            	system_processessb.append(line.trim()+"\n");
            }
            
		} catch (IOException e) {
			System.err.println("Problem getting list of processes");
			e.printStackTrace();
			return;
		}
		final String[] system_processes=system_processessb.toString().split("\n");
        
		//find the local ip
		final String localip=Inet4Address.getLocalHost().getHostAddress();
		System.out.println("Your local ip address is "+localip);
		
		
        /*************************************************************************** 
         * We enter the loop and tell it to capture packets. The loop 
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which 
         * is needed by JScanner. The scanner scans the packet buffer and decodes 
         * the headers. The mapping is done automatically, although a variation on 
         * the loop method exists that allows the programmer to sepecify exactly 
         * which protocol ID to use as the data link type for this pcap interface. 
         **************************************************************************/  
        
        //thread to listen for commands from user
        commands_listener_thread.start();
        
        //final BufferedWriter out = new BufferedWriter(new FileWriter("dump.txt"));
        //final BufferedWriter outcmd = new BufferedWriter(new FileWriter("dumpcmd.txt"));
		//outcmd.write(Arrays.toString(get_networked_processes())+"\n");
        
        pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Object>() {  
        	  
            /** 
             * We purposely define and allocate our working headers (accessor) 
             * outside the dispatch function and thus the libpcap loop, as this type 
             * of object is reusable and it would be a very big waste of time and 
             * resources to allocate it per every dispatch of a packet. We mark it 
             * final since we do not plan on allocating any other instances of them. 
             */  
            final Udp udp = new Udp();  
            final PcapPacket packet = new PcapPacket(JMemory.POINTER);  
            final Ip4 ip = new Ip4();  
            final Payload basePayload = new Payload();
            
            //main work here. We want to scan each incoming packet, and check the process its attached to.
            //TODO any way to work convo_id into this?
            public void nextPacket(PcapHeader header, JBuffer buffer, Object user) {  
            	packet.peerAndScan(Ethernet.ID, header, buffer);  
            	
            	String[] packetinfo = new String[5];
            	
            	packetinfo[0]=new Date(packet.getCaptureHeader().timestampInMillis()).toString();
            	
            	//Check if the packet has udp and ip headers. If so, get its ports and ips
            	//Steam w/ Dark Souls 2 uses udp protocol
            	if (packet.hasHeader(ip) && packet.hasHeader(udp) && packet.hasHeader(basePayload)){
            		packetinfo[1]=FormatUtils.ip(ip.source());
            		packetinfo[2]=String.valueOf(udp.source());
            		packetinfo[3]=FormatUtils.ip(ip.destination());
            		packetinfo[4]=String.valueOf(udp.destination());
            		
                	//TODO if its payload is a Binary Large Object, then this is the correct ip for the user, as this means we're sending player info to this ip
            		
	            	//we sucesfully got ips and ports
            		/*check if 1 we are the origin ip for the packet, 
            		 * 2 the destination ip has'nt been already added, 
            		 * 3 the destination ip isnt local
            		 */
            		boolean contains=false;
            		for(String[] a:recent_Dks2_ips){
            			if(a[3].equals(packetinfo[3])){// && a[2].equals(packetinfo[2]) && a[4].equals(packetinfo[4])){
            				contains=true;
            				break;
            			}
            		}
            		/* local ips are
            		10.0.0.0 - 10.255.255.255
            		172.16.0.0 - 172.31.255.255
            		192.168.0.0 - 192.168.255.255
            		*/
            		String[] ip=packetinfo[3].split("\\.");
            		boolean localdestination = ip[0].equals("10") || 
            				(ip[0].equals("172") && (Integer.parseInt(ip[1])>=16 && Integer.parseInt(ip[1])<=31)) ||
            				(ip[0].equals("192") && ip[1].equals("168"));
            		
	            	if(packetinfo[1].equals(localip) && !contains && !localdestination){
	            		try{
			            	//next we check the list of networked processes and get the one that has connections matching all 4 variables from the header
		            		String PiD=null;
		            		String processname=null;
		            		
		            		//i think we have to get list of networked processes every packet, as the connection is short-lived
		            		String[] networked_processes=get_networked_processes();
		            		
			            	for(String networked_process:networked_processes){
			            		//for these connections, it appears steam does it in LOCALIP:LOCALPORT *:* format, so forget checking the destination ip and port
								if(networked_process.contains(packetinfo[1]+":"+packetinfo[2]) /*&& networked_process.contains(packetinfo[3]+":"+packetinfo[4])*/){
									//we found the process for this packet, get its pid
									String[] process=networked_process.split("\\s+");
									PiD=process[process.length-1];
									break;
								}
			            	}
			            	
			            	//we only got the PID, so query the OS using the process ID and get the process name 
			            	if(PiD!=null){
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
			            	
				            	if(processname!=null){
					            	//if this process is steam, then we add the destination ip address (if its leaving local ip) to list of Dks2 player ips
					            	if(processname.equals("Steam.exe")){
					            		recent_Dks2_ips.add(packetinfo);
					            		//System.out.println(packet.getState().toDebugString());
					            		System.out.println("added Dks2 ip "+packetinfo[3]+" at "+packetinfo[0]);
					            	}
				            	}
				            	else{
				            		for(String process:system_processes){
					            		if(process.contains(PiD)){
					            			System.err.println("error getting process for Pid "+PiD+" for result "+process);
					            		}
				            		}
				            	}
			            	}
	            		}catch(IOException e){
	            			System.err.println("Unable to get list of all networked processes for this packet");
        				}
	            	}
            	}
            	
            	//to exit loop
            	if (exitloop) {
            		System.out.println("stopping");
            		pcap.breakloop();
            	}
            	
            	//to block user
            	//TODO until i fix the packet payload detection, the last recived ip is the correct one for the user
            	if(toblock){
            		String user_ip = recent_Dks2_ips.get(recent_Dks2_ips.size()-1)[3];
            		//String localport= recent_Dks2_ips.get(recent_Dks2_ips.size()-1)[2];
            		//String remoteport= recent_Dks2_ips.get(recent_Dks2_ips.size()-1)[4];
            		try {
            				block_user(user_ip.split("\\."));
						System.out.println("blocked user "+user_ip);
					} catch (IOException e) {
						System.out.println("error blocking user");
						e.printStackTrace();
					}
            		toblock=false;
            	}
            }
  
        }, errbuf);  
  
        /*************************************************************************** 
         * Last thing to do is close the pcap handle 
         **************************************************************************/  
        pcap.close(); 

	}

	
	private static void read_block_list() throws IOException {
		//first see if their is already a block list. if so, load it.
		File blocklist = new File("block.txt");
		if(blocklist.exists()){
			BufferedReader blockin = new BufferedReader(new FileReader("block.txt"));
			String line="";
			while ((line = blockin.readLine()) != null) { 
				//String[] blockinfo=new String[3];
				//blockinfo[0]=line.substring(3,line.indexOf("LP:"));
				//blockinfo[1]=line.substring(line.indexOf("LP:")+3,line.indexOf("RP:"));
				//blockinfo[2]=line.substring(line.indexOf("RP:")+3);
				blocked_Dks2_ips.add(line);
			}
			blockin.close();
		}
		
	}


	//get list of all networked processes
	public static String[] get_networked_processes() throws IOException{
    	StringBuffer networked_processessb=new StringBuffer();
		Process p = rt.exec("netstat -aon");
		commandoutput = new BufferedReader(new InputStreamReader(p.getInputStream()));
		String line = null;  
        while ((line = commandoutput.readLine()) != null) {  
        	networked_processessb.append(line.trim()+"\n");
        }
		return networked_processessb.toString().split("\n");
	}
	
	//we have to block an ip range (more testing needed for exact range), so make the range (try to make it as small as possible)
	private static String get_range(String[] user_ip){
		int last_ip_number = Integer.parseInt(user_ip[user_ip.length-1]);
		StringBuilder ip = new StringBuilder();
		for(int i=0;i<2;i++){
			for(int j=0;j<user_ip.length-1;j++){
				ip.append(user_ip[j]+".");
			}
			//block ip range by +-5
			if(i==0){
				int range=last_ip_number-0;
				if(range<0){
					ip.append("0"+"-");
				}else{
					ip.append(range+"-");
				}
			}else{
				int range=last_ip_number+0;
				if(range>255){
					ip.append("255");
				}else{
					ip.append(range);
				}
			}
		}
		return ip.toString();
	}
	
	//i have to block both the users remote it and the local ip they connect with. or something
	public static void block_user(String[] user_ip_array) throws IOException{
		//1:write block list to text
		BufferedWriter block_list = new BufferedWriter(new FileWriter("block.txt"));
		//rewrite the stored block list
		for(String blocked_ip:blocked_Dks2_ips){
			//block_list.write("IP:"+blocked_ip[0]);
			//block_list.write("LP:"+blocked_ip[1]);
			//block_list.write("RP:"+blocked_ip[2]);
			block_list.write(blocked_ip);
			block_list.newLine();
		}
		
		String user_ip=get_range(user_ip_array);
		//block_list.write("IP:"+user_ip);
		//block_list.write("LP:"+localport);
		//block_list.write("RP:"+remoteport);
		block_list.write(user_ip);
		block_list.close();
		
		blocked_Dks2_ips.add(user_ip);//new String[]{user_ip,localport,remoteport});
		
		//2:take the block list and add the ips to windows firewall
		//this need to run as administrator, and will fail if java doesnt start with admin power
		//first delete old rules
		rt.exec("netsh advfirewall firewall delete rule name=Dark_Souls_2_Blocks_out");
		rt.exec("netsh advfirewall firewall delete rule name=Dark_Souls_2_Blocks_in");
			
		//make list of blocked ips cmd friendly
		StringBuilder cmd_ip_listsb= new StringBuilder();
		StringBuilder cmd_lp_listsb= new StringBuilder();
		StringBuilder cmd_rp_listsb= new StringBuilder();
		for(String bip:blocked_Dks2_ips){
			cmd_ip_listsb.append(bip+",");
			//cmd_lp_listsb.append(bip[1]+",");
			//cmd_rp_listsb.append(bip[2]+",");
		}
		String cmd_ip_list=cmd_ip_listsb.toString();
		String cmd_lp_list=cmd_lp_listsb.toString();
		String cmd_rp_list=cmd_rp_listsb.toString();

		//TODO find steam.exe path. I need to ask the user on startup their steam.exe location. Also, save that info. might not be neccicary
		//create the rule blocking the ips
		//TODO WHY THE FUCK DOES THIS SOMETIMES JUST NOT WORK (i think it doesnt work if it doesnt exist beforehand)
		Process p = rt.exec("netsh advfirewall firewall add rule "
				+ "name=Dark_Souls_2_Blocks_out "
				+ "protocol=any "
				+ "dir=out "
				+ "action=block "
				+ "enable=yes "
				//+ "protocol=UDP "
				+ "remoteip="+cmd_ip_list);
				//+ "localport="+cmd_lp_list+" "
				//+ "remoteport="+cmd_rp_list);
			BufferedReader commandoutput = new BufferedReader(new InputStreamReader(p.getInputStream()));
	        String line = null;  
	        while ((line = commandoutput.readLine()) != null) {  
	        	System.out.print(line.trim()+"\n");
	        }
		Process l = rt.exec("netsh advfirewall firewall add rule "
				+ "name=Dark_Souls_2_Blocks_in "
				+ "protocol=any "
				+ "dir=in "
				+ "action=block "
				+ "enable=yes "
				//+ "protocol=UDP "
				+ "remoteip="+cmd_ip_list);
				//+ "localport="+cmd_lp_list+" "
				//+ "remoteport="+cmd_rp_list);
			commandoutput = new BufferedReader(new InputStreamReader(l.getInputStream()));
	        line = null;  
	        while ((line = commandoutput.readLine()) != null) {  
	        	System.out.print(line.trim()+"\n");
	        }
	}
}
