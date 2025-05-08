3 Analysis of SIEM Rules for Evasions
To lay the foundation for our work, we analyze a represen-
tative set of SIEM rules with respect to potential evasions.
For this purpose, we chose a subset of Sigma rules, which are
probably the most widely used corpus of open-source SIEM
rules at the moment. In the following, we give a short introduc-
tion to Sigma, describe our analysis goals and methodology,
and finally present our findings, showing that evasions indeed
induce significant detection blind spots.
Introduction to Sigma Rules Sigma is a generic and open
signature format for SIEM systems. It allows for flexible rules
in YAML format that can detect malicious or suspicious be-
havior in any type of text-based log data. Sigma rules can
be automatically converted to queries for common SIEM
products (e.g., Splunk or Elasticsearch). Aside from these
conversion tools and Sigma’s specification, its GitHub reposi-
tory [51] contains a large corpus of detection rules, which are
continuously revised and extended by a large community. Ac-
cording to the Open Source Security Index, the Sigma project
is among the most popular and fastest growing open source se-
curity projects on GitHub (sixth place overall, highest ranked
project with detection focus as of January 2023) [41]. In our
professional experience, Sigma rules are widely used by orga-
nizations in practice.
Analysis Goal and Methodology The goal of our analysis
was to quantify the risk of detection blind spots for existing
Sigma rules by finding concrete evasions for them. We had
to restrict our analysis to a subset of rules from the Sigma
repository due to the high effort of manual analysis and the
fact that some types of rules act on log data of software or
hardware that is not generally available (e.g., commercial
cloud services or appliances). We thus chose to analyze the
subset of rules that act on process creation events on Win-
dows systems. This rule type is the most frequent (making
up 41 % of all rules at the time of analysis) and does not
depend on log data from proprietary products except for Win-
dows. Furthermore, process creation events are known to be a
valuable source for threat detection [6]. They comprise infor-
mation on newly created processes and are generated either
by Windows itself [57] or by the tool Sysmon [46, 56]. The
contained fields most often searched by the Sigma process
creation rules are CommandLine (the full command line of the
process creation; 45 % of all search expressions in the consid-
ered rules), Image (the full path of the executed image; 29 %
of search expressions), and ParentImage (the full path of the
parent process image; 10 % of search expressions). There are
~20 more fields that are searched by only a few rules, e.g.,
Description, ParentCommandLine, and User.
The analysis was conducted as follows. We analyzed all
process creation rules that were contained in the Sigma repos-
itory on February 4, 2021 (commit ID 12054544). First, we
reviewed each rule in detail, including potential references
given within the rule (e.g., threat reports describing the ma-
licious behavior that should be detected by the rule). Next,
we tried to re-enact the malicious process creation as de-
scribed by the rule on a Windows 10 system (e.g., by running
powershell.exe /C Clear-EventLog System). We man-
ually reviewed the Windows event log to verify our commands
and then ran scripts to check for Sigma rules matching these
events. In case we succeeded to match the current rule, we
then tried to find command lines that perform the exact same
action, but without matching the rule (i.e., evasions).
USENIX Association 33rd USENIX Security Symposium 5181
Table 1: Almost half of the analyzed SIEM rules (129 of 292) can be evaded using the five straightforward evasion types presented
in this table (each with one concrete example), thus causing critical detection blind spots in enterprise networks.
Evasion type Sample affected rule Affected search term Sample match Sample evasion
Insertion win_susp_schtask_creation * /create * schtasks.exe /create ... schtasks.exe /"create" ...
Substitution win_susp_curl_download -O curl -O http://... curl --remote-name http://...
Omission win_mal_adwind *cscript.exe *Retrive*.vbs * cscript.exe ...\Retrive.vbs cscript ...\Retrive.vbs
Reordering win_susp_procdump * -ma ls* procdump -ma ls procdump ls -ma
Recoding win_vul_java_remote_dbg *address=127.0.0.1* ...address=127.0.0.1,... ...address=2130706433,...
For this to work, we assumed that an attacker who can
create a process with command line arguments is also able
to alter these arguments (e.g., curl.exe --remote-name
example.com instead of curl.exe -O example.com). We
made sure that successful evasions did not match any addi-
tional Sigma rules (i.e., rules not triggered by the original
match). Finally, we assigned one of four labels to each rule:
(1) full if we were able to completely evade the rule, (2) partial
if the rule contains OR-branches of which we could evade at
least one, but not all, (3) none if we could not find an evasion,
and (4) broken if we found the rule to be faulty.
Analysis Results Of the 292 analyzed Sigma rules, we
found that 110 (38 %) can be fully evaded and 19 (7 %) can be
partially evaded. For another 51 rules (17 %), we found that
evasion might be possible but could not confirm any concrete
evasion instances either due to unavailable target software
(mostly malware) or excessive effort for conclusive analysis.
We achieved all evasions by adapting the processes creation
command line in multiple ways. For this purpose, we found a
total of five evasion types during our analysis as exemplified
in Table 1: (1) Insertion of ignored characters into the com-
mand line (e.g., double quotes or spaces), (2) substitution of
synonymous characters or arguments (e.g., a hyphen instead
of a slash before an argument), (3) omission of unnecessary
characters (e.g., shortening arguments), (4) reordering of ar-
guments, and (5) recoding of arguments. We created at least
three matching and three evading events for each evadable
rule to achieve variability, ending up with 461 matches and
512 evasions in total, which were later used in the context of
our evaluation (cf. Section 6). Summarizing, we were able to
evade almost half of the rules, each with multiple variants.
We would like to emphasize that generally our results come
as no real surprise and are not necessarily specific to the ana-
lyzed Sigma rules. Instead, evasions are an intrinsic problem
of misuse detection due to the impracticality of covering every
possible mutation with hard-coded signatures (cf. Section 2).
This makes it practically impossible to “fix” the affected rules
in the sense of adapting them to detect all possible evasions.
However, a subsidiary result of our analysis is that we found
12 of the 292 rules to be broken, i.e., failing to detect what
was intended by the rule author. We excluded these rules from
our evasion analysis. Furthermore, we provided fixes to the
Sigma maintainers for all broken rules that had not yet been
fixed or removed by the Sigma community in the meantime,
resulting in four rules that were fixed through our feedback.
In conclusion, we find that the risk of detection blind spots
through rule evasions is indeed high for the analyzed Sigma
rules, which are widely used in practice. Even small attack
mutations using simple techniques suffice to evade detection.
Consequently, adversaries might remain undetected despite
performing commonly known attacks. In the following, we
therefore present our main idea, adaptive misuse detection,
which aims to solve this dilemma of easily-evadable rules by
classifying incoming SIEM events based on their similarity
to SIEM rules versus historical benign events.