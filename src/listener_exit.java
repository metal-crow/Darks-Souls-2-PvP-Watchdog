import java.util.Scanner;


public class listener_exit extends Thread{

	public void run() {
		System.out.println("Press e to exit");
        Scanner in = new Scanner(System.in);
        while(true){
        	String user=in.next();
        	if(user.toLowerCase().equals("e")){
        		watchdog_main.exitloop=true;
        	}
        	else{
        		watchdog_main.exitloop=false;
        	}
        }
    }

}
