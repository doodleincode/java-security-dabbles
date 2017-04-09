package net.awesomeapps.utils;

import java.util.ArrayList;
import java.util.List;

public class StringUtil {

	public static String lineWrap(String content, int length) {
		List<String> wrapped = new ArrayList<>();
		
	    while (content.length() > length) {
	    	wrapped.add(content.substring(0, length));
	    	content = content.substring(length);
	    }
	    
	    wrapped.add(content);
	    return String.join(System.lineSeparator(), wrapped);
	}
	
}
