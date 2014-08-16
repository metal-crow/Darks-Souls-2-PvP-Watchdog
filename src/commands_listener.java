import java.util.Scanner;


public class commands_listener extends Thread{
	
	public boolean listening=true;
	
	/* this thread listens to user commands while the watchdog packet sniffer loop runs
	 * used to end the program (stop the packer sniffer loop)
	 * or to get the most recent ip and block it
	 */
	public void run() {
		System.out.println("Press e to exit");
        Scanner in = new Scanner(System.in);
        while(listening){
        	String user=in.next();
        	if(user.toLowerCase().equals("e")){
        		watchdog_main.exitloop=true;
        	}
        	else{
        		watchdog_main.exitloop=false;
        	}
        }
        in.close();
    }

}
