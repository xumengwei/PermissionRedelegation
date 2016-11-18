package cn.edu.pku.echo.permission_redelegation;

import java.util.ArrayList;
import java.util.List;

import com.googlecode.d2j.Method;

public class API {
	public API(String c, String m, String p) {
		class_name = c;
		method_name = m;
		permission = p;
	}
	public String class_name;
	public String method_name;
	public String permission;
	public static List<API> sensitiveAPIs = new ArrayList<API>();
	static {
		sensitiveAPIs.add(new API("Landroid/net/wifi/WifiManager;", "setWifiEnabled", "CHANGE_WIFI_STATE"));
		sensitiveAPIs.add(new API("Landroid/telecom/TelecomManager;", "placeCall", "CALL_PHONE"));
		sensitiveAPIs.add(new API("Landroid/bluetooth/BluetoothAdapter;", "disable", "BLUETOOTH_ADMIN"));
		sensitiveAPIs.add(new API("Landroid/os/PowerManager$WakeLock;", "acquire", "WAKE_LOCK"));
		sensitiveAPIs.add(new API("Landroid/os/Vibrator;", "vibrate", "VIBRATE"));
		sensitiveAPIs.add(new API("Landroid/view/Window;", "setAttributes", "WRITE_SETTINGS"));
		sensitiveAPIs.add(new API("Landroid/provider/Settings$Global;", "putInt", "WRITE_SETTINGS"));
		sensitiveAPIs.add(new API("Landroid/provider/Settings$Global;", "putFloat", "WRITE_SETTINGS"));
		sensitiveAPIs.add(new API("Landroid/provider/Settings$Global;", "putString", "WRITE_SETTINGS"));
		sensitiveAPIs.add(new API("Landroid/provider/Settings$Global;", "putLong", "WRITE_SETTINGS"));
	}
	public static API isSensitiveAPI(Method method) {
		if (method == null) return null;
		for (API api : sensitiveAPIs) {
			if (api.class_name.equals(method.getOwner()) &&
					api.method_name.equals(method.getName()))
				return api;
		}
		return null;
	}
	@Override
	public boolean equals(Object o) {
		if (o == null || !(o instanceof API))
			return false;
		API api = (API) o;
		if (this.class_name.equals(api.class_name) &&
				this.method_name.equals(api.method_name))
			return true;
		return false;
	}
}