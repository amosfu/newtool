package concordia.ca.INSE6140;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import org.h2.tools.Server;

public class MainClass {

	private static final boolean OLD_SCHOOL_INJECTION = false;

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		// start the TCP Server
		Server server = Server.createTcpServer().start();
		//Class.forName("org.h2.Driver");
		Class.forName("com.mysql.jdbc.Driver");
        Connection conn = DriverManager.
            //getConnection("jdbc:p6spy:h2:~/test", "sa", ""); //original:jdbc:h2:~/test
        		getConnection("jdbc:p6spy:mysql://localhost/test", "root", "root");
        // add application code here
        ResultSet rs = null;
        if( OLD_SCHOOL_INJECTION ) {
            Statement st = conn.createStatement();
            String sql = "SELECT * FROM test WHERE name='%s' and id=%d";
            String name = "' or true=true or ''='";
            int id = 1;
            rs = st.executeQuery(String.format(sql, name, id));        	
        } else {
        	
            PreparedStatement ps = (PreparedStatement) conn.prepareStatement("SELECT * FROM test WHERE name=? and id=?");
            ps.setString(1, "' OR true=true or '=");
            ps.setInt(2, 1);
            rs = ps.executeQuery();
        }
        if( rs != null) {
        	while( rs.next() ) {
        		System.out.println("id: " + rs.getInt(1) + " Name: " + rs.getString(2));
        	}
        	rs.close();
        }
        conn.close();
		
		// stop the TCP Server
		server.stop();
		
	}

}
