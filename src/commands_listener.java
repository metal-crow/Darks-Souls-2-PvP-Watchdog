import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;


public class commands_listener extends Thread{
	
	private boolean listening=true;
	
	/* this thread listens to user commands while the watchdog packet sniffer loop runs
	 * used to end the program (stop the packer sniffer loop)
	 * or to get the most recent ip and block it
	 */
	public void run() {
		System.out.println("Type \"exit\" to exit, \"block\" to block last user");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        while(listening){
        	String user="";
        	try{
        		user=in.readLine();
        	}catch(IOException e){e.printStackTrace();}
        	if(user.toLowerCase().equals("exit")){
        		watchdog_main.exitloop=true;
        		listening=false;
        	}
        	if(user.toLowerCase().equals("block")){
        		watchdog_main.toblock=true;
        	}
        }
        try {
			in.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }

}
