package com.example.minitest;


public class Utility {

	public static String cleanInputAsString(String input) {
		return input;
	}
	
	public static Long cleanInputAsLong(String input) {
		Long result = null;
		try {
			result = Long.parseLong(input);
		} catch (NumberFormatException nfe) {
		}
		return result;
	}
	public static String encodeHtml(String input) {

		return input;
	}
}
