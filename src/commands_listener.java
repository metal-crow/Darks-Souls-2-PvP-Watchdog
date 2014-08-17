import java.util.Scanner;


public class commands_listener extends Thread{
	
	public boolean listening=true;
	
	/* this thread listens to user commands while the watchdog packet sniffer loop runs
	 * used to end the program (stop the packer sniffer loop)
	 * or to get the most recent ip and block it
	 */
	public void run() {
		System.out.println("Type \"exit\" to exit, \"block\" to block last user");
        Scanner in = new Scanner(System.in);
        while(listening){
        	String user=in.next();
        	if(user.toLowerCase().equals("exit")){
        		watchdog_main.exitloop=true;
        	}
        	if(user.toLowerCase().equals("block")){
        		watchdog_main.toblock=true;
        	}
        }
        in.close();
    }

}
