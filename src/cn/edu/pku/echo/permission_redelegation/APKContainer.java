package cn.edu.pku.echo.permission_redelegation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jdom2.Attribute;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.input.SAXBuilder;

import com.googlecode.d2j.Method;
import com.googlecode.d2j.node.DexClassNode;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.node.DexMethodNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.node.insn.MethodStmtNode;
import com.googlecode.d2j.reader.BaseDexFileReader;
import com.googlecode.d2j.reader.MultiDexFileReader;

public class APKContainer {
	private String apk_path = null;
	private String manifest_path = null;
	private Map<String, List<PublicEntry>> entries = new HashMap<String, List<PublicEntry>>();
	private Map<Method, Set<API>> API_maps = new HashMap<Method, Set<API>>();
	private Map<Method, Set<Method>> suc_maps = new HashMap<Method, Set<Method>>();
	public APKContainer(String path_to_apk, String path_to_manifest) {
		apk_path = path_to_apk;
		manifest_path = path_to_manifest;
		entries.put("service", new ArrayList<PublicEntry>());
		entries.put("receiver", new ArrayList<PublicEntry>());
	}
	public void parse() {
		parseManifest();
		parseAPK();
		List<Method> entryMethods = getEntryMethods();
		for (Method method: entryMethods) {
			Set<Method> all_suc_methods = new HashSet<Method>();
			all_suc_methods.add(method);
			all_suc_methods.addAll(suc_maps.get(method));
			for (int i = 0; i < 20; i ++) {
				Set<Method> temp = new HashSet<Method>();
				temp.addAll(all_suc_methods);
				for (Method tm : all_suc_methods)
					if (suc_maps.containsKey(tm))
						temp.addAll(suc_maps.get(tm));
				all_suc_methods = temp;
			}
			boolean flag = false;
			StringBuilder sb = new StringBuilder();
			sb.append(method.getOwner() + "\n");
			// System.out.println(method.getOwner() + ": " + all_suc_methods.size());
			for (Method suc_method : all_suc_methods) {
				boolean tflag = false;
				StringBuilder temp = new StringBuilder();
				temp.append("\t" + suc_method.getOwner() + "->" + suc_method.getName() + "\n");
				if (API_maps.containsKey(suc_method)) {
					flag = true;
					tflag = true;
					Set<API> apis = API_maps.get(suc_method);
					for (API api : apis) {
						temp.append("\t\t" + api.class_name + "->" + api.method_name + "\n");
					}
				}
				if (tflag)
					sb.append(temp.toString());
			}
			if (flag)
				System.out.print(sb.toString());
		}
	}
	private List<Method> getEntryMethods() {
		List<Method> ret = new ArrayList<Method>();
		for (Method method : suc_maps.keySet()) {
			for (PublicEntry entry : entries.get("receiver")) {
				String ename = "L" + entry.name.replace(".", "/") + ";";
				// System.out.println(ename + "," + method.getOwner());
				if (ename.equals(method.getOwner()) && 
						method.getName().equals("onReceive")) {
					ret.add(method);
					break;
				}
			}
			for (PublicEntry entry : entries.get("service")) {
				String ename = "L" + entry.name.replace(".", "/") + ";";
				// System.out.println(ename + "," + method.getOwner());
				if (ename.equals(method.getOwner()) && 
						method.getName().equals("onHandleIntent")) {
					ret.add(method);
					break;
				}
			}
		}
		return ret;
	}
	private void parseAPK() {
		Path path = Paths.get(apk_path);
		BaseDexFileReader dfr = null;
		byte[] stream;
		try {
			stream = Files.readAllBytes(path);
			dfr = MultiDexFileReader.open(stream);
		} catch (IOException e) {
			e.printStackTrace();
		}
		int clsNumber = dfr.getClassNames().size();
		System.out.println("App: " + apk_path + ", Class Number: " + clsNumber + "\n");
		DexFileNode dfn = new DexFileNode();
		dfr.accept(dfn);
		for (DexClassNode dcn : dfn.clzs) {
			if (dcn == null || dcn.methods == null)
				continue;
			for (DexMethodNode dmn : dcn.methods) {
				if (dmn == null || dmn.codeNode == null)
					continue;
				for (DexStmtNode dsn : dmn.codeNode.stmts) {
					if (!(dsn instanceof MethodStmtNode))
						continue;
					MethodStmtNode msn = (MethodStmtNode) dsn;
					Method source = dmn.method;
					Method target = msn.method;
					API api = API.isSensitiveAPI(target);
					if (api != null) {
						if (!API_maps.containsKey(source))
							API_maps.put(source, new HashSet<API>());
						API_maps.get(source).add(api);
					}
					if (!suc_maps.containsKey(source))
						suc_maps.put(source, new HashSet<Method>());
					suc_maps.get(source).add(target);
				}
			}
		}
	}
	private void parseManifest() {
		try {
			SAXBuilder builder = new SAXBuilder();
			Document document = builder.build(manifest_path);
			Element root = document.getRootElement();
			Element application = root.getChild("application");
			String default_perm = null;
			for (Attribute attr : application.getAttributes())
				if (attr.getName().equals("permission"))
					default_perm = attr.getValue();
			List<Element> receivers = application.getChildren("receiver");
			for (Element ele : receivers)
				addEntry(ele, default_perm, "receiver");
			List<Element> services = application.getChildren("service");
			for (Element ele : services)
				addEntry(ele, default_perm, "service");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void addEntry(Element ele, String default_perm, String type) {
		List<Element> filters = ele.getChildren("intent-filter");
		String name = null;
		String permission = default_perm;
		boolean exported = (filters != null);
		for (Attribute attr : ele.getAttributes()) {
			if (attr.getName().equals("exported"))
				exported = attr.getValue().equals("true");
			if (attr.getName().equals("name"))
				name = attr.getValue();
			if (attr.getName().equals("permission"))
				permission = attr.getValue();
		}
		if (!exported || name == null) return;
		List<String> actions = new ArrayList<String>();
		for (Element filter : filters) {
			List<Element> act_elements = filter.getChildren("action");
			for (Element act : act_elements) {
				for (Attribute attr : act.getAttributes())
					if (attr.getName().equals("name"))
						actions.add(attr.getValue());
			}
		}
		entries.get(type).add(new PublicEntry(name, permission, actions));
	}
}

class PublicEntry {
	String name;
	List<String> actions;
	String permission;
	public PublicEntry (String _name, String _permission, List<String> _actions) {
		name = _name;
		permission = _permission;
		actions = _actions;
	}
	public String getDesc() {
		return name;
	}
}