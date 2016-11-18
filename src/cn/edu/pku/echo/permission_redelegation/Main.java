package cn.edu.pku.echo.permission_redelegation;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Main {
	public static void main(String[] args) {
		List<String> apks = getFileList("/Users/echo/Documents/Lab/MyProject/AndroidWear/apks/");
		for (String apk : apks) {
			if (!apk.endsWith(".apk")) continue;
			APKContainer container = new APKContainer(apk, apk.substring(0, apk.length() - 4) + "/AndroidManifest.xml");
			container.parse();
		}
	}
	public static List<String> getFileList(String dir) {
	    List<String> listFile = new ArrayList<>();
	    File dirFile = new File(dir);
	    if (dirFile.isDirectory()) {
	        File[] files = dirFile.listFiles();
	        if (null != files && files.length > 0) {
	            for (File file : files)
	                if (!file.isDirectory())
	                    listFile.add(file.getAbsolutePath());
	        }
	    }
	    return listFile;
	}
}
