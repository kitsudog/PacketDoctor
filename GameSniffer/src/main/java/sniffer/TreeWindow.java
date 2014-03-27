package sniffer;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeSet;

import org.apache.pivot.beans.BXML;
import org.apache.pivot.beans.Bindable;
import org.apache.pivot.collections.Map;
import org.apache.pivot.collections.Sequence;
import org.apache.pivot.collections.Sequence.Tree.Path;
import org.apache.pivot.util.Resources;
import org.apache.pivot.wtk.Action;
import org.apache.pivot.wtk.ApplicationContext;
import org.apache.pivot.wtk.Component;
import org.apache.pivot.wtk.Menu;
import org.apache.pivot.wtk.MenuHandler;
import org.apache.pivot.wtk.Point;
import org.apache.pivot.wtk.ScrollPane;
import org.apache.pivot.wtk.TreeView;
import org.apache.pivot.wtk.TreeView.SelectMode;
import org.apache.pivot.wtk.Window;
import org.apache.pivot.wtk.content.TreeBranch;
import org.apache.pivot.wtk.content.TreeNode;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class TreeWindow extends Window implements IOut, Bindable {

	@BXML
	private TreeView tree;

	@BXML
	private ScrollPane pane;

	// @BXML
	// private TextInput includeText;
	//
	// @BXML
	// private TextInput excludeText;

	private TreeBranch root;

	private boolean dirty;

	private Set<String> include = new HashSet<String>();

	private Set<String> exclude = new HashSet<String>();

	private MenuHandler menuHandler = new MenuHandler.Adapter() {
		@Override
		public boolean configureContextMenu(Component component, Menu menu,
				int x, int y) {
			Point pt = getDisplay().getMouseLocation();
			pt = tree.mapPointFromAncestor(getDisplay(), pt);
			Path path = tree.getNodeAt(pt.y);
			TreeNode node = (TreeNode) Sequence.Tree.get(tree.getTreeData(),
					path);
			final MessageData data = (MessageData) node.getUserData();
			// 选中所有的
			Sequence<Path> paths = new org.apache.pivot.collections.ArrayList<Sequence.Tree.Path>();
			int len = root.getLength();
			for (int i = 0; i < len; i++) {
				TreeNode treeNode = root.get(i);
				MessageData item = (MessageData) treeNode.getUserData();
				if (item.msgId.equals(data.msgId)) {
					paths.add(new Path(i));
				}
			}
			tree.setSelectMode(SelectMode.MULTI);
			tree.setSelectedPaths(paths);
			// 设置菜单
			Menu.Section menuSection = new Menu.Section();
			menu.getSections().add(menuSection);
			Menu.Item includeMenu = new Menu.Item(String.format("包含 %s",
					data.msgId));
			includeMenu.setAction(new Action() {
				@Override
				public void perform(Component source) {
					include.add(data.msgId);
					reload();
				}
			});
			menuSection.add(includeMenu);
			Menu.Item excludeMenu = new Menu.Item(String.format("排除 %s",
					data.msgId));
			excludeMenu.setAction(new Action() {
				@Override
				public void perform(Component source) {
					exclude.add(data.msgId);
					reload();
				}
			});
			menuSection.add(excludeMenu);
			Menu.Item resetMenu = new Menu.Item("重置过滤条件");
			resetMenu.setAction(new Action() {
				@Override
				public void perform(Component source) {
					include.clear();
					exclude.clear();
					reload();
				}

			});
			menuSection.add(resetMenu);
			Menu.Item cleanMenu = new Menu.Item("清空");
			cleanMenu.setAction(new Action() {
				@Override
				public void perform(Component source) {
					allData.clear();
					reload();
				}

			});
			menuSection.add(cleanMenu);
			return false;
		}
	};

	private ArrayList<MessageData> allData = new ArrayList<IOut.MessageData>();

	private void reload() {
		// if (include.size() == 0)
		// {
		// includeText.setText("*");
		// }
		// else
		// {
		// includeText.setText(include.toString());
		// }
		// if (exclude.size() == 0)
		// {
		// excludeText.setText("NULL");
		// }
		// else
		// {
		// excludeText.setText(exclude.toString());
		// }
		ApplicationContext.queueCallback(new Runnable() {

			@Override
			public void run() {
				TreeBranch treeData = new TreeBranch();
				tree.setTreeData(treeData);
				for (int i = 0; i < allData.size(); i++) {
					MessageData node = allData.get(i);
					if (exclude.contains(node.msgId)) {
						// 被过滤了
						continue;
					}
					if (include.size() > 0 && !include.contains(node.msgId)) {
						// 被过滤了
						continue;
					}
					treeData.add(getNode(node));
				}
				tree.setTreeData(treeData);
				root = treeData;
			}
		});
	}

	public void addNode(final MessageData node) {
		allData.add(node);
		if (exclude.contains(node.msgId)) {
			// 被过滤了
			return;
		}
		if (include.size() > 0 && !include.contains(node.msgId)) {
			// 被过滤了
			return;
		}
		ApplicationContext.queueCallback(new Runnable() {

			@Override
			public void run() {
				synchronized (root) {
					root.add(getNode(node));
				}
			}

		});
		dirty = true;
	}

	private TreeNode getNode(MessageData node) {
		if (node.content == null) {
			TreeNode treeNode = new TreeNode(node.title);
			treeNode.setUserData(node);
			return treeNode;
		} else {
			TreeNode treeNode = newJsonNode(node.content, node.title);
			treeNode.setUserData(node);
			return treeNode;
		}
	}

	@SuppressWarnings("unchecked")
	private TreeNode newJsonNode(JSONObject json, Object title) {
		TreeBranch node = new TreeBranch(title.toString());
		ArrayList<String> nodes = new ArrayList<String>();
		int maxLen = 0;
		for (Object key : new TreeSet<Object>(json.keySet()).toArray()) {
			Object value = json.get(key);
			if (value instanceof JSONObject) {
				node.add(newJsonNode((JSONObject) value, key));
			} else if (value instanceof JSONArray) {
				node.add(newJsonNode((JSONArray) value, key));
			} else {
				nodes.add((String) key);
				maxLen = Math.max(maxLen, ((String) key).length());
			}
		}
		for (String key : nodes) {
			Object value = json.get(key);
			String template = "%-30s\t:%s";
			if (value instanceof String) {
				template = "%-30s\t:\"%s\"";
			}
			node.add(new TreeNode(String.format(template, key, value)));
		}
		return node;
	}

	private TreeNode newJsonNode(JSONArray json, Object title) {
		TreeBranch node = new TreeBranch(title.toString());
		int i = 0;
		for (Object value : json.toArray()) {
			if (value instanceof JSONObject) {
				node.add(newJsonNode((JSONObject) value, i));
			} else if (value instanceof JSONArray) {
				node.add(newJsonNode((JSONArray) value, i));
			}
			i++;
		}
		return node;
	}

	@Override
	public void initialize(Map<String, Object> namespace, URL location,
			Resources resources) {
		tree.setMenuHandler(menuHandler);
		tree.setTreeData(root = new TreeBranch());
		Timer timer = new Timer();
		timer.schedule(new TimerTask() {

			@Override
			public void run() {
				if (dirty) {
					try {
						tree.repaint(true);
						dirty = false;
					} catch (Exception e) {
						System.err.println("刷新异常 " + e);
					}
				}
			}
		}, 1000, 1000);
	}
}
