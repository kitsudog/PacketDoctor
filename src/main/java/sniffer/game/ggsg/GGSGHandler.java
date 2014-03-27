package sniffer.game.ggsg;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Date;
import java.util.Iterator;

import org.apache.pivot.collections.HashSet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import simlife.game.sanguo.command.CommandSet;
import simlife.game.sanguo.command.stCommand;
import sniffer.IOut.MessageData;

public class GGSGHandler extends HttpHandler {
	private static HashSet<String> SKIP = new HashSet<String>();
	static {
		SKIP.add("getClass");
		SKIP.add("getModule");
		SKIP.add("getAction");
		SKIP.add("getVerison");
		SKIP.add("isDebug");
		SKIP.add("getCmdStatus");
		SKIP.add("getUID");
	}

	@Override
	protected void doHttp(Request request, Response response) {
		if (!request.uri.endsWith("/msg") && !request.uri.endsWith("/chat")) {
			System.out.println("Pass " + request.url);
			return;
		}
		JSONObject json = null;
		try {
			CommandSet commandSetReq = new CommandSet();
			if (request.content != null) {
				commandSetReq.unpack(new DataInputStream(
						new ByteArrayInputStream(request.content)));
			}
			appendCommand(commandSetReq, MessageData.TYPE_SEND);
			CommandSet commandSetRsp = new CommandSet();
			if (response.content != null) {
				commandSetRsp.unpack(new DataInputStream(
						new ByteArrayInputStream(response.content)));
			}
			appendCommand(commandSetRsp, MessageData.TYPE_RECV);
		} catch (IOException e) {
			System.err.println("ERROR:" + e);
			System.err.println(request);
			System.err.println(response);
		}
	}

	private void appendCommand(CommandSet commandSet, int type) {
		for (stCommand command : commandSet.getCommandList()) {
			JSONObject json = new JSONObject();
			String msgid = command.getModule() + "_" + command.getAction();
			for (Method method : command.getClass().getMethods()) {
				if (SKIP.contains(method.getName())) {
					continue;
				}
				if (method.getName().startsWith("get")
						|| method.getName().startsWith("is")) {
					try {
						Object tmp = method.invoke(command);
						Object value = tmp;
						if (tmp != null && tmp.getClass().isArray()) {
							value = new JSONArray();
							if (tmp instanceof Object[]) {
								for (Object obj : (Object[]) tmp) {
									((JSONArray) value).add(obj);
								}
							} else if (tmp instanceof int[]) {
								for (int obj : (int[]) tmp) {
									((JSONArray) value).add(obj);
								}
							} else if (tmp instanceof long[]) {
								for (long obj : (long[]) tmp) {
									((JSONArray) value).add(obj);
								}
							} else if (tmp instanceof byte[]) {
								for (byte obj : (byte[]) tmp) {
									((JSONArray) value).add(obj);
								}
							} else if (tmp instanceof short[]) {
								for (short obj : (short[]) tmp) {
									((JSONArray) value).add(obj);
								}
							} else if (tmp instanceof boolean[]) {
								for (boolean obj : (boolean[]) tmp) {
									((JSONArray) value).add(obj);
								}
							}
						} else if (tmp != null && tmp instanceof Iterable) {
							value = new JSONArray();
							Iterator it = ((Iterable) tmp).iterator();
							while (it.hasNext()) {
								Object obj = it.next();
								((JSONArray) value).add(obj);
							}
						}
						json.put(method.getName().replace("get", ""), value);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
			json.put("#UID#", commandSet.getUID());
			json.put("#SESSIONID#", commandSet.getSessionID());
			out.addNode(new MessageData(new Date(), msgid, type, command
					.getClass().getName(), json, null));
		}
	}
}
