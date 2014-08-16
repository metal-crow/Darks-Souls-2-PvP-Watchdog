import java.util.Scanner;


public class commands_listener extends Thread{
	
	public boolean listening=true;
	
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
