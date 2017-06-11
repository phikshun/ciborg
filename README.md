CIborg
======

CIborg is an automated CI/CD assessment, post-exploitation and takeover tool.

The basic process CIborg follows:
* Scan for CI systems using the parameters supplied
* Upon finding a CI system, use various exploits and misconfigurations to gain control and extract secrets
* Examine the build logs to locate systems where secrets can be used to gain a shell or access to another CI system
* Extract secrets from those systems and use logs, netstat output, bash_history and other data to determine target systems for those secrets
* Optionally execute commands or install post-exploitation tools along each hop of the graph
* Generate reports to understand the scope of compromise
