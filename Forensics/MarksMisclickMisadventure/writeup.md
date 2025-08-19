## Writeup

Analyzing the PCAP you will see its a standard LNK file malware loader with ransomware. The first stage is the user downloading a ZIP file with an LNK.
This then triggers more downloads to a remote server and downloads extra files. The ransomware is then run which exfiltrates the encrypted files through DNS to the remote server. The process is:

1) Download the LNK and reverse its process
2) Find the actual malware it downloads and runs
3) Reverse engineer this .net DLL to see how files are encrypted
4) Extract the DNS data and decrypt it

Export HTTP Objects. This gives you m0zisaskid.zip.
If you step throug the TCP stream for this, you will also find the "email" from the hacker stating the password to the zip is `supersecurepassword`

Run exfil tool on this to see its command. Reverse the base64 string to see it downloads https://minge.skin/backup.bat
Downloading this file you see it downloads the malware: https://minge.skin/mmm.exe

This file is actually a .NET dll. So you can load it in DNSpy to see the source code.

Viewing the source code you see some noteable functions:

**AES Encrypt Function**
```
static string GetMac()
		{
			var nic = NetworkInterface
				.GetAllNetworkInterfaces()
				.FirstOrDefault(n =>
					n.NetworkInterfaceType == NetworkInterfaceType.Ethernet &&
					n.OperationalStatus == OperationalStatus.Up);

			return nic?.GetPhysicalAddress().ToString() ?? "000000000000";
		}

		static byte[] GetKeyFromMac()
		{
			string mac = GetMac();
			if (mac.Length < 16)
				mac = mac.PadRight(16, '0');
			return Encoding.UTF8.GetBytes(mac.Substring(0, 16));
		}
```

**IV Defined Statically**

```
    static readonly byte[] aesIV = new byte[] {
			0x13, 0x37, 0x00, 0x42, 0x23, 0x01, 0x0C, 0xBE,
			0xEF, 0x10, 0x11, 0x12, 0x20, 0x21, 0x22, 0x23
        };
```

**Mac address used as Key in AES**
```
    	static string GetMac()
		{
			var nic = NetworkInterface
				.GetAllNetworkInterfaces()
				.FirstOrDefault(n =>
					n.NetworkInterfaceType == NetworkInterfaceType.Ethernet &&
					n.OperationalStatus == OperationalStatus.Up);

			return nic?.GetPhysicalAddress().ToString() ?? "000000000000";
		}

		static byte[] GetKeyFromMac()
		{
			string mac = GetMac();
			if (mac.Length < 16)
				mac = mac.PadRight(16, '0');
			return Encoding.UTF8.GetBytes(mac.Substring(0, 16));
		}

```

**Exfil files through DNS**
```
	static string GetMac()
		{
			var nic = NetworkInterface
				.GetAllNetworkInterfaces()
				.FirstOrDefault(n =>
					n.NetworkInterfaceType == NetworkInterfaceType.Ethernet &&
					n.OperationalStatus == OperationalStatus.Up);

			return nic?.GetPhysicalAddress().ToString() ?? "000000000000";
		}

		static byte[] GetKeyFromMac()
		{
			string mac = GetMac();
			if (mac.Length < 16)
				mac = mac.PadRight(16, '0');
			return Encoding.UTF8.GetBytes(mac.Substring(0, 16));
		}

```

With all this you can solve the challenge. I used Cyberchef and manually submitted all the DNS requests for the flag.txt file:

https://gchq.github.io/CyberChef/#recipe=Unique('Line%20feed',false)Find_/_Replace(%7B'option':'Regex','string':'.minge.skin%5C%5Cn'%7D,'',true,false,true,false)AES_Decrypt(%7B'option':'Hex','string':'30383030323746343846443230303030'%7D,%7B'option':'Hex','string':'1337004223010CBEEF10111220212223'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=YTY2NDg5ZDM0NmU2ZTc1NzNjOGMyNTQxMTQwYjc3Lm1pbmdlLnNraW4KYTY2NDg5ZDM0NmU2ZTc1NzNjOGMyNTQxMTQwYjc3Lm1pbmdlLnNraW4KYTY2NDg5ZDM0NmU2ZTc1NzNjOGMyNTQxMTQwYjc3Lm1pbmdlLnNraW4KYTY2NDg5ZDM0NmU2ZTc1NzNjOGMyNTQxMTQwYjc3Lm1pbmdlLnNraW4KZjI2NDQ4ODAyNTYxYzgwMTU2ODU3ZWU4ZWQ0OTgyLm1pbmdlLnNraW4KZjI2NDQ4ODAyNTYxYzgwMTU2ODU3ZWU4ZWQ0OTgyLm1pbmdlLnNraW4KZjI2NDQ4ODAyNTYxYzgwMTU2ODU3ZWU4ZWQ0OTgyLm1pbmdlLnNraW4KZjI2NDQ4ODAyNTYxYzgwMTU2ODU3ZWU4ZWQ0OTgyLm1pbmdlLnNraW4KYTcwNTQ5OWY0MDc2MWM5MTJjNzM3YjUwZWRkY2Y3Lm1pbmdlLnNraW4KYTcwNTQ5OWY0MDc2MWM5MTJjNzM3YjUwZWRkY2Y3Lm1pbmdlLnNraW4KYWI3YmQ3Zjg2ZWU5NDkzMGM4NTE3NjE0ZDNjNjBjLm1pbmdlLnNraW4KYWI3YmQ3Zjg2ZWU5NDkzMGM4NTE3NjE0ZDNjNjBjLm1pbmdlLnNraW4KYWI3YmQ3Zjg2ZWU5NDkzMGM4NTE3NjE0ZDNjNjBjLm1pbmdlLnNraW4KYWI3YmQ3Zjg2ZWU5NDkzMGM4NTE3NjE0ZDNjNjBjLm1pbmdlLnNraW4KMmY4NGJmYzg2ZDhiZmU5NWIzYThmNTM4YWUzOWM4Lm1pbmdlLnNraW4KMmY4NGJmYzg2ZDhiZmU5NWIzYThmNTM4YWUzOWM4Lm1pbmdlLnNraW4KYzJmZmM4YmU4Mi5taW5nZS5za2luCmMyZmZjOGJlODIubWluZ2Uuc2tpbgpjMmZmYzhiZTgyLm1pbmdlLnNraW4KYzJmZmM4YmU4Mi5taW5nZS5za2luCgo&oeol=FF
