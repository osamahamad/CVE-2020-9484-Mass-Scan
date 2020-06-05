## CVE-2020-9484-Mass-Scan
CVE-2020-9484 Mass Scanner, Scan a list of urls against Apache Tomcat deserialization (CVE-2020-9484) which could lead to RCE, determine possible vulnerable hosts.


```
The web application will return HTTP 500 error upon exploitation, because it encounters a malicious serialized object instead of one that contains session information as it expects.
```


```
The Exploit:
Tomcat requests the Manager to check if a session with session ID “../../../../../../tmp/12345” exists
It will first check if it has that session in memory.
It does not. But the currently running Manager is a PersistentManager, so it will also check if it has the session on disk.
It will check at location directory + sessionid + ".session", which evaluates to “./session/../../../../../../tmp/12345.session“
If the file exists, it will deserialize it and parse the session information from it
```


Source: https://www.redtimmy.com/java-hacking/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/ 


```targets.txt```

```
https://example.com
http://example:8080
http://example.com/

```

[Vuln Docker + PoC](https://github.com/masahiro331/CVE-2020-9484)

```./run.sh targets.txt ../../../../../usr/local/tomcat/groovy > result.txt ```

```cat result.txt | grep "SUCCESS"```



## References 
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484

https://meterpreter.org/cve-2020-9484-apache-tomcat-remote-code-execution-vulnerability-alert/

https://github.com/masahiro331/CVE-2020-9484

https://www.redtimmy.com/java-hacking/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/



