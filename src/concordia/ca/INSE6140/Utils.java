package concordia.ca.INSE6140;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.input.ReversedLinesFileReader;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.mail.*;  
import javax.mail.internet.*;  
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * Created by Amos on 2017-03-05.
 * Modified by Carlos on 2017-03-13.
 */
public class Utils {
    public static final File STATIC_TEMP = new File("./static_temp.txt");
    public static final String USAGE = "Usage: (static|dynamic) (source code/log path)";
    private static String[] mailRecipients = null;
    private static String from = null;  
    
    private static final String REGEX = "(INSERT |UPDATE |SELECT |WITH |DELETE )([^;]*)";
    private static final Pattern PATTERN = Pattern.compile(REGEX);
    
    private static final Logger logger = LogManager.getLogger(Utils.class);

    public static void extractSQLFromCode(File srcDir) throws IOException {
        String[] extensions = {"java", "jsp"};
        Collection<File> files = FileUtils.listFiles(srcDir, extensions, true);
        int counter = 0;
        BufferedWriter bw = new BufferedWriter(new FileWriter(STATIC_TEMP));
        for (File file : files) {
            String tempFile = "";
            Utils.logMessage(file.getName());
            tempFile = FileUtils.readFileToString(file);
            for (String tempSQL : Utils.generateSQLTemplate(tempFile)) {
                bw.write(tempSQL);
                bw.newLine();
                counter++;
            }
        }
        bw.flush();
        bw.close();
        Utils.logMessage("SQL count: " + counter);
    }

    public static Map<Integer,String> loadStaticAnalysisLog(File staticLogFile) throws IOException  {
        if (!staticLogFile.exists()) {
        	Utils.logMessage( "static_temp.txt doesn't exist!\n" + Utils.USAGE);
        	return null;
        }
        Map<Integer,String> hashFile = new HashMap<>();
        BufferedReader tempReader = new BufferedReader(new FileReader(staticLogFile));
        for (String sqlLine = tempReader.readLine(); null != sqlLine; sqlLine = tempReader.readLine()) {
            hashFile.put(sqlLine.hashCode(),sqlLine);
        }
        tempReader.close();

        return hashFile;
    }

    public static boolean processDynamicQuery(String logEntry, Map<Integer,String> staticQueryRepo)  {

    	boolean possibleAttack = false;
    	
		if( logEntry != null ) {
			//Query found.
            String[] components = logEntry.split("<<\\|[O|P]{0,1}>>");
            Utils.logMessage("processDynamicQuery: " +components.length + " components found: ");
            Utils.logMessage(Arrays.toString(components));
            
            if( components.length == 6) {
            	Utils.logMessage("processDynamicQuery: 6 components");
                String suspiciousSQLTemp = components[components.length - 2];
                String preparedSQL = components[components.length - 1];
                String canonicalSQLTemplate = generateSQLTemplate(preparedSQL).get(0);
    			String templateQuery = staticQueryRepo.get(canonicalSQLTemplate.hashCode());
    			Utils.logMessage("processDynamicQuery: found queries: ");
            	Utils.logMessage("processDynamicQuery: suspiciousSQLTemp:");
            	Utils.logMessage(suspiciousSQLTemp);
            	Utils.logMessage("processDynamicQuery: preparedSQL:");
            	Utils.logMessage(preparedSQL);
            	Utils.logMessage("processDynamicQuery: canonicalSQLTemplate:");
            	Utils.logMessage(canonicalSQLTemplate);
            	Utils.logMessage("processDynamicQuery: templateQuery:");
            	Utils.logMessage(templateQuery);
                if (templateQuery == null) {
                    Utils.logMessage("processDynamicQuery: Not found on the repo... the query is suspicious.");
                    List<String> potentialTempSQLs= generateSQLTemplate(suspiciousSQLTemp);
                    Utils.logMessage("processDynamicQuery: potentialTempSQLs:");
                    Utils.logMessage(potentialTempSQLs != null? Arrays.toString(potentialTempSQLs.toArray()) : "null");
                    if(!potentialTempSQLs.isEmpty()){
                        suspiciousSQLTemp = potentialTempSQLs.get(0);
                    }
                    if (!suspiciousSQLTemp.equalsIgnoreCase(canonicalSQLTemplate)) {
                    	possibleAttack = true;
                    	Utils.logMessage(canonicalSQLTemplate);
                    	Utils.logMessage("Attack found!\n" + canonicalSQLTemplate);
                    }
                }
            }
            else if( components.length == 5) {
            	Utils.logMessage("processDynamicQuery: 5 components");
                String suspiciousSQLTemp = components[components.length - 1];
                String canonicalSQLTemplate = generateSQLTemplate(suspiciousSQLTemp).get(0);
    			String templateQuery = staticQueryRepo.get(canonicalSQLTemplate.hashCode());
    			Utils.logMessage("processDynamicQuery: found queries: ");
            	Utils.logMessage("processDynamicQuery: suspiciousSQLTemp:");
            	Utils.logMessage(suspiciousSQLTemp);
            	Utils.logMessage("processDynamicQuery: canonicalSQLTemplate:");
            	Utils.logMessage(canonicalSQLTemplate);
            	Utils.logMessage("processDynamicQuery: templateQuery:");
            	Utils.logMessage(templateQuery);
                if (templateQuery == null) { //Not found on the repo... the query is suspicious
                    Utils.logMessage("processDynamicQuery: Not found on the repo... the query is suspicious.");
                    List<String> potentialTempSQLs= generateSQLTemplate(suspiciousSQLTemp);
                    Utils.logMessage("processDynamicQuery: potentialTempSQLs:");
                    Utils.logMessage(potentialTempSQLs != null? Arrays.toString(potentialTempSQLs.toArray()) : "null");
                    if(!potentialTempSQLs.isEmpty()){
                        suspiciousSQLTemp = potentialTempSQLs.get(0);
                    }
                    if (!suspiciousSQLTemp.equalsIgnoreCase(canonicalSQLTemplate)) {
                    	possibleAttack = true;
                    	Utils.logMessage(canonicalSQLTemplate);
                    	Utils.logMessage("Attack found!\n" + canonicalSQLTemplate);
                    }
                }
            }
		}
    	
        return possibleAttack;
    }
    
	public static boolean notifyPossibleAttack(String suspiciousLogEntry) {
	  
		  boolean result = false;
		  InputStream inputProp = null;
		  
	      try{  
		     Properties properties = new Properties();  
		     inputProp = Utils.class.getClassLoader().getResourceAsStream("mail.properties");
		     properties.load(inputProp);
		     Session session = Session.getInstance(properties,new javax.mail.Authenticator() {
					protected PasswordAuthentication getPasswordAuthentication() {
						return new PasswordAuthentication(properties.getProperty("user"),properties.getProperty("password"));
					}
				  });  
		     mailRecipients = properties.getProperty("recipients").split(",");
		     from =  properties.getProperty("from");

		     MimeMessage message = new MimeMessage(session);
	         message.setFrom(new InternetAddress(from));  
	         for( String recipient : mailRecipients ) {
	        	 message.addRecipient(Message.RecipientType.TO,new InternetAddress(recipient));
	         }
	         message.setSubject("Possible attack:");  
	         message.setText(String.format("Hello, we have detected a possible SQL injection attack.\n\nDetails: %s", suspiciousLogEntry));  
	  
	         // Send message  
	         Transport.send(message);  
	         Utils.logMessage("notifyPossibleAttack: message sent successfully...."); 
	         result = true;
	  
	      }catch (MessagingException | IOException mex) {mex.printStackTrace();}  
	      
	      return result;
	}
	
	public static Map<Long,String> getLogLastLine(File dynamicLogFile, long previousTime) {
		Map<Long,String> result = new HashMap<>();
		result.put(-1L, ""); //default

		try (@SuppressWarnings("deprecation")
		ReversedLinesFileReader reader = new ReversedLinesFileReader(dynamicLogFile)) {
	        String line = null;
	        String previousLine = null;
	        while ((line = reader.readLine()) != null ) {
	        	int idx = line.indexOf(SqlFormatPrettyfier.GENERAL_SEPARATOR);
	            if(idx > -1) {
	            	long currentVal = Long.parseLong(line.substring(0, idx));
	            	if( currentVal <= previousTime ) {
	            		if( previousLine == null ) {
	            			previousLine = line;
	            		}
	            		idx = previousLine.indexOf(SqlFormatPrettyfier.GENERAL_SEPARATOR);	            			
	            		long time = Long.parseLong(previousLine.substring(0, idx));
	            		result.clear();
	            		result.put(time, previousLine);
	            		break;
	            	}
	            }
            	previousLine = line;
	        }
	    } catch (IOException e) {
	    	Utils.logMessage("Cannot get the last time output in log.");
	    	Utils.logMessage(e.getStackTrace().toString(),Type.ERROR);
		}		
		
		return result;
	}

/*
    public static boolean extractSQLFromLog(File dbLogFile) throws IOException, InterruptedException {
        if (!STATIC_TEMP.exists()) {
        	System.out.println( "static_temp.txt doesn't exist!\n" + Utils.USAGE);
        	return false;
        }
        BufferedReader tempReader = new BufferedReader(new FileReader(STATIC_TEMP));
        List<String> tempSQLs = new ArrayList<>();
        for (String sqlLine = tempReader.readLine(); null != sqlLine; sqlLine = tempReader.readLine()) {
            tempSQLs.add(sqlLine);
        }
        tempReader.close();

        while (true) {
            BufferedReader logReader = new BufferedReader(new FileReader(dbLogFile));
            for (String logLine = logReader.readLine(); null != logLine; logLine = logReader.readLine()) {
                String[] components = logLine.split("\\|");
                String actualSQL = components[components.length - 1];
                String potentialSQLTemp = components[components.length - 2];
                String actualSQLTemp = generateSQLTemplate(actualSQL).get(0);
                if (!tempSQLs.contains(actualSQLTemp)) {
                    List<String> potentialTempSQLs= generateSQLTemplate(potentialSQLTemp);
                    if(!potentialTempSQLs.isEmpty()){
                        potentialSQLTemp = potentialTempSQLs.get(0);
                    }
                    if (!potentialSQLTemp.equalsIgnoreCase(actualSQLTemp)) {
                        System.out.println(actualSQLTemp);
                        System.out.println("Attack found!\n" + actualSQL);
                    }
                }
            }
            PrintWriter writer = new PrintWriter(dbLogFile);
            writer.print("");
            writer.close();
            logReader.close();
        }
        return true;
    }
*/

    public static List<String> generateSQLTemplate(String strInput) {
        List<String> templates = new ArrayList<>();
        Matcher m = PATTERN.matcher(strInput);

        for (boolean isFind = m.find(); isFind; ) {
            String tempSQL = m.group(1) + m.group(2);
            tempSQL = tempSQL.trim();
            tempSQL = tempSQL.replaceAll("\"[^\"]*\"", "?");
            tempSQL = tempSQL.replaceAll("\"", "");
            tempSQL = tempSQL.replaceAll("\'[^\']*\'", "?");
            tempSQL = tempSQL.replaceAll("\\s*", "");
            tempSQL = tempSQL.replaceAll("\\+.*\\)", "?");
            tempSQL = tempSQL.replaceAll("=\\d+", "=?");
            tempSQL = tempSQL.replaceAll(",\\d+", ",?");
            tempSQL = tempSQL.replaceAll("\\(\\d+", "(?");
            templates.add(tempSQL);
            isFind = m.find();
        }
        return templates;
    }

    public static void printUsage() {
    	Utils.logMessage(USAGE);
    }
    
    public enum Type {
    	INFO,
    	ERROR
    }
    
    public static void logMessage(String message, Type... type) {
    	Type t;
    	if( type.length == 0 ) 
    		t = Type.INFO;
    	else
    		t = type[0];
    	
    	if( t == Type.INFO) {
    		logger.info(message);
    		System.out.println(message);
    	}
    	else {
    		logger.error(message);
    		System.err.println(message);
    	}
    }
    
}
