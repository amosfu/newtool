package concordia.ca.INSE6140;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.sun.nio.file.SensitivityWatchEventModifier;

import static java.nio.file.StandardWatchEventKinds.*;

import concordia.ca.INSE6140.Utils.Type;

public class Agent extends Thread {
	
	File pathToStaticLog;
	File dynamicLogFile;
	
	private final WatchService watcher;
    private final Map<WatchKey,Path> keys;
    
	public Agent(File pathToStaticLog, File dynamicLogFile) throws IOException {
		this.pathToStaticLog = pathToStaticLog;
		this.dynamicLogFile = dynamicLogFile;
		this.watcher = FileSystems.getDefault().newWatchService();
        this.keys = new HashMap<WatchKey,Path>();
	}
	 @SuppressWarnings("unchecked")
	 static <T> WatchEvent<T> cast(WatchEvent<?> event) {
	        return (WatchEvent<T>)event;
	 }
	 
	@Override
	public void run() {
		// Step 1 - Static 
		Utils.logMessage("Processing static analisys log.");
		Map<Integer,String> staticLog = null;
		try {
			staticLog = Utils.loadStaticAnalysisLog(this.pathToStaticLog);
		} catch (IOException e) {
			Utils.logMessage("An error has occured during retrieving of the static log: \n" + e.getStackTrace().toString(),Type.ERROR);

		}
		
		if(staticLog == null) {
			Utils.logMessage("Agent has no static queries to compare against. If some prepared statements are found, they will be used for comparison.");
		}

		// Step 2 - Monitoring application execution through the log
		Utils.logMessage("Dynamic stage initiated.");
		try {
			registerForChange();
		} catch (IOException e) {
			Utils.logMessage("A fatal error has occured during registration for changes in the dynamic log file. Agent will shut down!: \n" + e.getStackTrace().toString(),Type.ERROR);
			return;
		}
		
		long time = Long.MAX_VALUE;
				
		while(true) {
			String currentLine = null;
			try {
				// wait for key to be signalled
				//WatchKey key;
				//key = watcher.take();
				// Path dir = keys.get(key);

				//if (dir == null) {
				//    System.err.println("WatchKey not recognized!!");
				//    continue;
				//}

				//for (WatchEvent<?> event: key.pollEvents()) {
				//    final WatchEvent.Kind kind = event.kind();

				//if (kind == ENTRY_MODIFY) {
				// Context for directory entry event is the file name of entry
				//        WatchEvent<Path> ev = cast(event);
				//        Path name = ev.context();
				//       Path child = dir.resolve(name);

				// print out event
				//        System.out.format("Filesystem event has been detected in %s: %s\n", event.kind().name(), child);

				Utils.logMessage("Processing dynamic log.");
				Map<Long,String> lastLine = getLastLine(time);
				if( !lastLine.containsKey(-1L) ) {
					time = lastLine.keySet().iterator().next();
					currentLine = lastLine.get(time);
					Utils.logMessage("Current time " + time + ". line: " + currentLine);
					processDynamicLog(currentLine,staticLog);
				}
				else {
					Utils.logMessage("Query detected, but there is nothing to process this time.");
				}
				Thread.sleep(500);
				//}
				//}

				// reset key and remove from set if directory no longer accessible
				// boolean valid = key.reset();
				// if (!valid) {
				//      keys.remove(key);

				// all directories are inaccessible
				//   if (keys.isEmpty()) {
				//  	Utils.logMessage("Agent cannot find anything to monitor. It will shut down!",Type.ERROR);
				//      break;
				// }
			}
			catch (InterruptedException e) {
				//unregisterForChange();
				Utils.logMessage("An error has occurred while accessing the dynamic log: \n" + e.getStackTrace().toString(),Type.ERROR);
			}
		}
//		Utils.logMessage("Agent to shutdown.");
	}
	
	private void processDynamicLog(String logEntry,Map<Integer,String> staticQueryRepo) {
		if( Utils.processDynamicQuery(logEntry,staticQueryRepo) ) {
			Utils.notifyPossibleAttack(logEntry);
		}
	}


	private Map<Long,String> getLastLine(long previousTime) {
		return Utils.getLogLastLine(dynamicLogFile, previousTime);
	}

	private void registerForChange() throws IOException {
		Path dir = Paths.get(dynamicLogFile.getParent());
        WatchKey key = dir.register(watcher, new WatchEvent.Kind[]{StandardWatchEventKinds.ENTRY_MODIFY}, SensitivityWatchEventModifier.HIGH);
        keys.put(key, dir);
    }
	
	private void unregisterForChange() {
		// TODO Auto-generated method stub
	}


}
