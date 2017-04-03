package concordia.ca.INSE6140;

import java.io.File;
import java.io.IOException;

import static java.lang.System.exit;

public class Main {

    public static void main(String[] args) throws IOException, InterruptedException {

    	if(args.length < 2){
        	System.out.println(Utils.USAGE);
            exit(1);
        }

        if("static".equalsIgnoreCase(args[0])) {
            Utils.extractSQLFromCode(new File(args[1]));
        }else if("dynamic".equalsIgnoreCase(args[0])){
        	Agent a = new Agent(Utils.STATIC_TEMP, new File(args[1]),"spy.log");
        	a.start();
        	Utils.logMessage("Dynamic agent has started successfully.");
            //Utils.extractSQLFromLog(new File(args[1]));
        }else{
        	Utils.logMessage("Unsupported Operation :" + args[0]);
            Utils.printUsage();
        }
    }
}
