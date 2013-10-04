package com.axway.ssc.oauth.shared;

import java.util.Enumeration;
import java.util.Properties;
import java.util.ResourceBundle;

/**
 * Property file load as a resource
 * 
 * @author cmanda
 * 
 */
public class ConfigLoad {
	public static Properties config = new Properties();
	private static final String BUNDLE_NAME = "config";

	private ConfigLoad() {

		System.out.println("loading config....");
		ResourceBundle bundle = ResourceBundle.getBundle(BUNDLE_NAME);
		Enumeration<String> keys = bundle.getKeys();
		while (keys.hasMoreElements()) {
			String key = keys.nextElement();
			config.setProperty(key, bundle.getString(key));
			System.out.println(key + " : " + bundle.getString(key));

		}
	}

	@SuppressWarnings("unused")
	public static String get(String key) {
		if (config.isEmpty()) {
			ConfigLoad cl = new ConfigLoad();
			return config.getProperty(key);
		}
		return config.getProperty(key);
	}

	public static void main(String[] args) {

		System.out.println("PRT: " + ConfigLoad.get("port"));
		System.out.println("PRT: " + ConfigLoad.get("port"));
		System.out.println("PRT: " + ConfigLoad.get("port"));

	}

}
