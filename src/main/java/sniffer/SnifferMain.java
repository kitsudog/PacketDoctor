package sniffer;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

import javax.swing.JOptionPane;

import org.apache.pivot.wtk.Alert;
import org.apache.pivot.wtk.DesktopApplicationContext;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.game.ggsg.GGSGHandler;
import sniffer.game.ggsg.HandlerFactory;

public class SnifferMain {

	public static void main(String[] args) throws IOException {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
														// NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		// 额外的dll拷贝到临时目录中去
		try {
			System.loadLibrary("jnetpcap");
		} catch (Throwable e) {
			String arch = System.getProperty("os.arch");
			String libpath = System.getProperty("java.library.path");
			if (libpath == null || libpath.length() == 0) {
				throw new RuntimeException("无法自动释放jnetpcap.dll");
			}
			String path = null;
			StringTokenizer st = new StringTokenizer(libpath,
					System.getProperty("path.separator"));

			while (true) {
				if (!st.hasMoreTokens()) {
					System.exit(1);
				}
				path = st.nextToken();
				File temporaryDll = new File(new File(path), "jnetpcap.dll");
				if (temporaryDll.exists()) {
					break;
				}
				try {
					FileOutputStream outputStream = new FileOutputStream(
							temporaryDll);
					byte[] array = new byte[8192];
					InputStream dllStream = SnifferMain.class
							.getResourceAsStream(arch.equals("x86") ? "jnetpcap.dll"
									: "jnetpcap-64.dll");
					for (int i = dllStream.read(array); i != -1; i = dllStream
							.read(array)) {
						outputStream.write(array, 0, i);
					}
					outputStream.flush();
					outputStream.close();
					dllStream.close();
					info("释放dll到目录 " + path);
					try {
						System.load(temporaryDll.getPath());
						info("使用临时目录的dll " + path);
						break;
					} catch (Throwable e2) {
						info("无法使用dll" + path + " " + e2.getMessage());
					}
				} catch (Throwable e1) {
					// 尝试下一个
					info("无法释放dll到目录" + path + " " + e1.getMessage());
					if (temporaryDll.exists()) {
						temporaryDll.delete();
					}
				}

			}
		}

		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			output(String.format("无法读取网卡列表, error is %s", errbuf.toString()));
			return;
		}
		String msg = "";
		msg += ("找到的网卡:") + "\n";
		int cnt = 0;
		for (PcapIf device : alldevs) {
			String description = (device.getDescription() != null) ? device
					.getDescription() : "没有合法的描述";
			msg += (String.format("#%d: %s [%s]\n", cnt++, device.getName(),
					description)) + "\n";
		}
		msg += "#999: Loop [127.0.0.1]\n";
		PcapIf device;
		int id = args.length > 0 ? Integer.parseInt(args[0]) : -1;
		while (!((id < alldevs.size() || id == 999) && id >= 0)) {
			try {
				// Prompt.prompt("123", Window.getActiveWindow());
				String line = JOptionPane.showInputDialog(msg + "\n"
						+ "输入目标网卡序号");
				if (line == null) {
					System.exit(1);
				}
				id = Integer.parseInt(line);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		int port = args.length > 1 ? Integer.parseInt(args[1]) : -1;
		while (port <= 0) {
			try {
				String line = JOptionPane.showInputDialog("输入目标端口号", "8001");
				if (line == null) {
					System.exit(1);
				}
				port = Integer.parseInt(line);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		DesktopApplicationContext.main(PivotApplication.class, new String[] {});
		while (PivotApplication.window == null) {
			try {
				System.err.println("Wait");
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		HandlerFactory handlerFactory = new HandlerFactory(GGSGHandler.class,
				(IOut) PivotApplication.window);
		if (id == 999) {
			File temporaryExe = File.createTempFile("RawPcap", ".exe");
			FileOutputStream outputStream = new FileOutputStream(temporaryExe);
			byte[] array = new byte[8192];
			InputStream exeStream = SnifferMain.class
					.getResourceAsStream("RawCap.exe");
			for (int j = exeStream.read(array); j != -1; j = exeStream
					.read(array)) {
				outputStream.write(array, 0, j);
			}
			outputStream.flush();
			outputStream.close();
			exeStream.close();
			Process proc = Runtime.getRuntime().exec(
					temporaryExe.getAbsolutePath() + " -h");
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					proc.getInputStream()));
			String line;
			int devid = -1;
			while ((line = reader.readLine()) != null) {
				if (line.indexOf("127.0.0.1") > 0) {
					devid = Integer.parseInt(line.split("\\.")[0].trim());
					break;
				}
			}
			if (devid == -1) {
				output("无法挂载loop");
				System.exit(1);
			}
			File tempFile = File.createTempFile("dump", ".pcap");
			// 正式启动cap
			try {
				final Process subproc = Runtime.getRuntime().exec(
						temporaryExe.getAbsolutePath() + " -f " + devid + " "
								+ tempFile.getAbsolutePath());
				Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
					@Override
					public void run() {
						subproc.destroy();
					}
				}));

				FileInputStream input = new EndlessFileInputStream(tempFile);
				DataInputStream din = new DataInputStream(input);
				// // 标识位
				// int magic = din.readInt();// 0xa1b2c3d4
				// // 主版本号
				// short version_major = din.readShort(); // 0x0002
				// // 副版本号
				// short version_minor = din.readShort();// 0x0004
				// // 区域时间
				// int thiszone = din.readInt();
				// // 精确时间戳
				// int sigfigs = din.readInt();
				// // 数据包最大长度
				// int snaplen = din.readInt();
				// // 链路层类型
				// int linktype = din.readInt();
				cnt = 0;
				while (true) {
					// pcap_pkthdr
					byte[] pcap_pkthdr = new byte[16];
					din.readFully(pcap_pkthdr);
					byte b = din.readByte();
					int v = b >> 4;
					assert (v == 4);
					int headLen = (b & 0x0F) * 4;
					byte[] ipBuff = new byte[headLen];
					ipBuff[0] = b;
					din.readFully(ipBuff, 1, headLen - 1);
					DataInputStream ipDin = new DataInputStream(
							new ByteArrayInputStream(ipBuff));
					ipDin.readShort();
					short totalLen = ipDin.readShort();
					byte[] buffer = new byte[totalLen + 16];
					for (int j = 0; j < 16; j++) {
						buffer[j] = pcap_pkthdr[j];
					}
					for (int j = 0; j < headLen; j++) {
						buffer[j + 16] = ipBuff[j];
					}
					din.readFully(buffer, headLen + 16, totalLen - headLen);
					ipDin.close();
					cnt++;
					try {
						JMemoryPacket packet = new JMemoryPacket(
								JProtocol.IP4_ID, Arrays.copyOfRange(buffer,
										16, buffer.length));
						Tcp tcp = packet.getHeader(new Tcp());
						Ip4 ip4 = packet.getHeader(new Ip4());
						handlerFactory.getHandler(ip4, tcp).nextPacket(ip4,
								tcp, System.currentTimeMillis());
						if (cnt > 1000000) {
							break;
						}
					} catch (Throwable e) {
						System.err.println("无法解析的包 " + cnt);
						byte[] buff = Arrays.copyOfRange(buffer, 16,
								buffer.length);
						for (int i = 0; i < buff.length; i++) {
							System.err.print(String.format("%02x ", buff[i]));
							if ((i + 1) % 16 == 0) {
								System.err.println();
							}
						}
						System.err.println();
						e.printStackTrace();
					}
				}
				din.close();
				subproc.destroy();
				tempFile.delete();
				temporaryExe.delete();
			} catch (SecurityException e) {
				Alert.alert("请使用管理员的cmd启动", PivotApplication.window);
			}
		} else {
			device = alldevs.get(id);
			int snaplen = 64 * 1024; // Capture all packets, no trucation
			int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
			int timeout = 10 * 1000; // 10 seconds in millis
			Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags,
					timeout, errbuf);
			while (cnt < 1000000) {
				pcap.loop(100, handlerFactory, "jNetPcap rocks!");
			}
			pcap.close();

		}
		JOptionPane.showMessageDialog(null, "捕获结束");
	}

	private static void info(String msg) {
		System.out.println(msg);
	}

	private static void output(String msg) {
		System.err.println(msg);
		Alert.alert(msg, PivotApplication.window);
	}
}