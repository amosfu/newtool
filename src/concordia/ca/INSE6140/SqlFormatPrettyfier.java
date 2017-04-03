package concordia.ca.INSE6140;

import com.p6spy.engine.spy.appender.MessageFormattingStrategy;

public class SqlFormatPrettyfier implements MessageFormattingStrategy {

	public static final String GENERAL_SEPARATOR = "<<|>>";
	private static final String ORIGINAL_SQL_SEPARATOR = "<<|O>>";
	private static final String ORIGINAL_PREPARED_SQL_SEPARATOR = "<<|P>>";

	@Override
	public String formatMessage(int connectionId, String now, long elapsed, String category, String prepared, String sql) {
		StringBuilder sb = new StringBuilder( now + GENERAL_SEPARATOR + elapsed + GENERAL_SEPARATOR + category + GENERAL_SEPARATOR+"connection " + connectionId );
		if( sql == null || sql.isEmpty() ) 
			sb.append(ORIGINAL_SQL_SEPARATOR + prepared);
		else
			sb.append(ORIGINAL_SQL_SEPARATOR + sql + ORIGINAL_PREPARED_SQL_SEPARATOR + prepared);
		return sb.toString();
	}

}
