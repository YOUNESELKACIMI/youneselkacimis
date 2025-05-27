# ModSecurity WAF and OWASP CRS project : Testing plan and fine tuning

# How CRS Works and Reviewing and Documentation of some rules of REQUEST-942-APPLICATION-ATTACK-SQLI.conf file:

# Architecture :

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled.png)

# ModSecurity Rules Structure :

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%201.png)

# Understand Anomaly Scoring :

Anomaly scoring, also called “collaborative detection,” assigns a numerical score to HTTP transactions (requests and responses), representing how “anomaly” they are. Anomaly scores can then be used to make blocking decisions.

Individual rules designed to detect specific types of attacks and malicious behavior are executed. If a rule matches, no immediate disruptive action is taken (e.g. the transaction is not blocked). Instead, the matched rule contributes to a transactional *anomaly score*, which acts as a running total. The rules just handle detection, adding to the anomaly score if they match. In addition, an individual matched rule will typically log a record of the match for later reference, including the ID of the matched rule, the data that caused the match, and the URI that was being requested.

Once all of the rules that inspect *request* data have been executed, *blocking evaluation* takes place. If the anomaly score is greater than or equal to the inbound anomaly score threshold then the transaction is *denied*. Transactions that are not denied continue on their journey.

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%202.png)

Each rule is associated with a “Severity” level. Different severity levels are associated with different anomaly scores. This means that different rules can increase the anomaly score by different amounts if the rules match.

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%203.png)

Example :

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%204.png)

The “Severity” parameter is set to CRITICAL, which means that this rule is going to contribute to incrementing the anomaly score by 5, therefore contributing to the blocking decision.

# Understanding Paranoia Levels

**The paranoia level (PL) makes it possible to define how aggressive CRS is.** Paranoia level 1 (PL 1) provides a set of rules that hardly ever trigger a false alarm (ideally never, but it can happen, depending on the local setup). PL 2 provides additional rules that detect more attacks (these rules operate *in addition* to the PL 1 rules), but there’s a chance that the additional rules will also trigger new false alarms over perfectly legitimate HTTP requests.

This continues at PL 3, where more rules are added, namely for certain specialized attacks. This leads to even more false alarms. Then at PL 4, the rules are so aggressive that they detect almost every possible attack, yet they also flag a lot of legitimate traffic as malicious.

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%205.png)

# Rule - Paranoia Level 1 :

<aside>
💡 Basic SQL Injection

</aside>

```bash
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)union.*?select.*?from" \
    "id:942270,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Looking for basic sql injection. Common attack string for mysql, oracle and others',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## **Rule breakdown :**

<aside>
⚙ SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/

</aside>

This part specifies the variables that the rule inspects which are :

1. REQUEST_COOKIES : all cookies in the request
2. !REQUEST_COOKIES:/__utm/ :  excludes the cookie with name matching __utm 
3. REQUEST_COOKIES_NAMES : names of all the cookies
4. ARGS_NAMES :  names of all the arguments (parameters) 
5. ARGS : all the arguments ( parameters)
6. XML:/* : all the elements in the XML payload if the request body is in XML

<aside>
⚙ @rx (?i)union.*?select.*?from

</aside>

This is the operator part, it inspects the variables with a condition to be matched using regular expression @rx

1. (?i) :  it makes the regex using case insensitive matching
2. union.*?select.*?from :  selects payloads with union followed by select followed by from with any caracters in between

<aside>
⚙ id:942270 : Specifies a unique id for the rule

</aside>

<aside>
⚙ phase:2 : specifies that the matching is done in the 2nd phase; the REQUEST_BODY phase

</aside>

<aside>
⚙ block : action to take if the rule matches

</aside>

<aside>
⚙ capture : captures matched mata for logging purposes

</aside>

<aside>
⚙ t: Transformation to apply to data before matching. t:none : resets transformations, t:urlDecodeUni :  decode URL-encoded characters, includes unicode encoding

</aside>

<aside>
⚙ msg:'Looking for basic sql injection. Common attack string for mysql, oracle and others’ is the message to log if the rule matches

</aside>

<aside>
⚙ logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}’, Additional data to log if the rule matches, it includes the Matched Data  “%{TX.0}” ( this captures the exact part of the part that matched the regex pattern ) within the matched variable %{MATCHED_VAR_NAME}

</aside>

<aside>
⚙ tags

</aside>

- application-multi, language-multi, platform-multi : indicate that this rule is cross application,language and platform
- attack-sqli : indicates the rule is related to SQL injection
- paranoia-level/1: indicating that the paranoia level is 1
- OWASP_CRS , OWASP_CRS/WEB_ATTACK/SQL_INJECTION : indicates that the rule is part of the owasp core set rules used against SQL injections
- WASCTC/WASC-19 : Web Application Security Consortium threat classification for SQL injection
- OWASP_TOP_10/A1 : Owasp top 10 SQL injection category
- OWASP_AppSensor/CIE1 : OWASP AppSensor category for detecting injection attacks.
- PCI/6.5.2 : PCI DSS requirements for protecting web applications from SQL injections.

<aside>
⚙ ver:'OWASP_CRS/3.2.0’ : indicates the version of the owasp CRS this rule belongs to

</aside>

<aside>
⚙ severity:'CRITICAL’ :  Indicates the severity level of the rule if it matches

</aside>

<aside>
⚙ Score Adjustements

</aside>

- setvar: ‘ tx.sql_injection_score=+%{tx.critical_anomaly_score}’ : increases the ‘sql_injection_score’ transactional variable by the ‘tx.critical_anomaly_score’. for tracking the sql injection score which enables us to identify how severe and frequent SQL injections attempts and for action taking purposes when it arrives to a certain treshold.
- setvar:’tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}’ : increases the transactional variable ‘tx.anomaly_score_pl1’ by ‘tx.critical_anomaly_score’, which helps track the anomay score in the paranoia level 1 and aids in actions taking purposes when it arrives to a certain treshold

## Isolation and Testing of this rule

```bash
cd /etc/modsecurity/
vim RULE1_PARANOIA_L1_Basic_SQL_Injection.conf # copy the basic sql injection rule
```

/etc/modsecurity/rules/RULE1_PARANOIA_L1_Basic_SQL_Injection.conf

```bash
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)union.*?select.*?from" \
    "id:942270,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Looking for basic sql injection. Common attack string for mysql, oracle and others',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

```

```bash
	vim /etc/apache2/mdos-enabled/security.conf # comment the inclusion of the other rules 
	# and include the testing rule
	
```

```bash
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier

        #IncludeOptional /etc/modsecurity/*.conf
        #Include /etc/modsecurity/rules/*.conf

        #including our testing rule
        Include /etc/modsecurity/rules/RULE1_PARANOIA_L1_Basic_SQL_Injection.conf
				#Include /etc/modsecurity/rules/RULE2_PARANOIA_L2_Basic_SQL_Injection.conf
				#Include /etc/modsecurity/rules/RULE3_PARANOIA_L3_Basic_SQL_Injection.conf
        #Include /etc/modsecurity/rules/RULE4_PARANOIA_L4_Basic_SQL_Injection.conf
        
        # Include OWASP ModSecurity CRS rules if installed
        #IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>

```

```bash
systemctl restart apache2
```

## Testing of the rule’s triggering

Check the apache error logs for incoming logs

```sql
tail -f /var/log/apache2/error.log
```

we test the following SQL injection payload inside the DVWA webserver trough the reverse proxy with the modsecurity WAF

```sql
1 UNION SELECT username, password FROM users
```

<aside>
⛔ WAF successfully detects and blocks the attack (Payload successfully triggers the rule and increments the anomaly score by 5)

</aside>

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%206.png)

# Rule  - Paranoia Level 2:

<aside>
💡 SQL Hex Evasion Methods

</aside>

```bash
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i:\b0x[a-f\d]{3,})" \
    "id:942450,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Hex Encoding Identified',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/2',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## **Rule breakdown :**

<aside>
⚙ SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*

</aside>

This part specifies the variables that the rules is going to inspect

- REQUEST_COOKIES : Inspects all the cookies in the request
- !REQUEST_COOKIES:/__utm/ : Exclude the cookie with name __utm from the inspection
- !REQUEST_COOKIES:/_pk_ref/ : Exclude the cookie with name *pk_ref* from the inspection
- REQUEST_COOKIES_NAMES : Inspect all the cookies names in the request
- ARGS_NAMES : Inspect all the arguments(parameters) names
- ARGS : Inspect all the arguments(parameters)
- XML: /* :  Inspect all elements of the XML payload if the request body is in XML

<aside>
⚙ "@rx (?i:\b0x[a-f\d]{3,})"

</aside>

This is the operator part it inspects the variables with a condition to be matched using regex @rx

1. (?i:) : makes the regex case insensitive
2.  \b: this is a word boundary, used to detect the beginning and the end of a word
3. 0x: this a literal string used to represent a hexadecimal value
4. [a-f\d]{3,} : 
    1. [a-f\d] : this character class matches any single character from a to f or any digit from 0 to 9
    2. {3,} : this ensures that the preceding character class should appear at least 3 times

<aside>
⚙ To summarize, the regex `(?i:\b0x[a-f\d]{3,})` matches a string that:

- Starts at a word boundary,
- Begins with the prefix `0x`,
- Followed by at least three hexadecimal digits (0-9, a-f, case-insensitive).
</aside>

<aside>
⚙ id:94250 : Specifies a unique id for the rule

</aside>

<aside>
⚙ phase:2 : specifies that the matching is done in the 2nd phase; the REQUEST_BODY phase

</aside>

<aside>
⚙ block : action to take if the rule matches

</aside>

<aside>
⚙ capture : captures matched mata for logging purposes

</aside>

<aside>
⚙ t: Transformation to apply to data before matching. t:none : resets transformations, t:urlDecodeUni :  decode URL-encoded characters, includes unicode encoding

</aside>

<aside>
⚙ msg:'SQL Hex Encoding Identified’

</aside>

<aside>
⚙ logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}’, Additional data to log if the rule matches, it includes the Matched Data  “%{TX.0}” ( this captures the exact part of the part that matched the regex pattern ) within the matched variable %{MATCHED_VAR_NAME}

</aside>

<aside>
⚙ tags

</aside>

- application-multi, language-multi, platform-multi : indicate that this rule is cross application,language and platform
- attack-sqli : indicates the rule is related to SQL injection
- paranoia-level/1: indicating that the paranoia level is 1
- OWASP_CRS , OWASP_CRS/WEB_ATTACK/SQL_INJECTION : indicates that the rule is part of the owasp core set rules used against SQL injections
- WASCTC/WASC-19 : Web Application Security Consortium threat classification for SQL injection
- OWASP_TOP_10/A1 : Owasp top 10 SQL injection category
- OWASP_AppSensor/CIE1 : OWASP AppSensor category for detecting injection attacks.
- PCI/6.5.2 : PCI DSS requirements for protecting web applications from SQL injections.

<aside>
⚙ ver:'OWASP_CRS/3.2.0’ : indicates the version of the owasp CRS this rule belongs to

</aside>

<aside>
⚙ severity:'CRITICAL’ :  Indicates the severity level of the rule if it matches

</aside>

<aside>
⚙ Score Adjustements

</aside>

- setvar: ‘ tx.sql_injection_score=+%{tx.critical_anomaly_score}’ : increases the ‘sql_injection_score’ transactional variable by the ‘tx.critical_anomaly_score’. for tracking the sql injection score which enables us to identify how severe and frequent SQL injections attempts and for action taking purposes when it arrives to a certain treshold.
- setvar:’tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}’ : increases the transactional variable ‘tx.anomaly_score_pl2’ by ‘tx.critical_anomaly_score’, which helps track the anomay score in the paranoia level 2 and aids in actions taking purposes when it arrives to a certain treshold

## Isolation and Testing of this rule

/etc/modsecurity/rules/RULE2_PARANOIA_L2_Basic_SQL_Injection.conf

```bash
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i:\b0x[a-f\d]{3,})" \
    "id:942450,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Hex Encoding Identified',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/2',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

```bash
	vim /etc/apache2/mdos-enabled/security.conf # comment the inclusion of the other rules 
	# and include the testing rule
	
```

```bash
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier

        #IncludeOptional /etc/modsecurity/*.conf
        #Include /etc/modsecurity/rules/*.conf

        #including our testing rule
        #Include /etc/modsecurity/rules/RULE1_PARANOIA_L1_Basic_SQL_Injection.conf
				Include /etc/modsecurity/rules/RULE2_PARANOIA_L2_Basic_SQL_Injection.conf
				#Include /etc/modsecurity/rules/RULE3_PARANOIA_L3_Basic_SQL_Injection.conf
        #Include /etc/modsecurity/rules/RULE4_PARANOIA_L4_Basic_SQL_Injection.conf
        
        # Include OWASP ModSecurity CRS rules if installed
        #IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>

```

```bash
systemctl restart apache2
```

## Testing of the rule’s triggering

Check the apache error logs for incoming logs

```sql
tail -f /var/log/apache2/error.log
```

we test the following SQL injection payload inside the DVWA webserver trough the reverse proxy with the modsecurity WAF

```sql
1' UNION SELECT 0x757365726e616d65, 0x70617373776f7264 FROM users-- 
```

this SQL injection payload mean 1' UNION SELECT users, password from users —

<aside>
⛔ WAF successfully detects and blocks the attack (Payload successfully triggers the rule and increments the anomaly score by 5)

</aside>

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%207.png)

# Rule - Paranoia Level 3:

<aside>
💡 Detect SQLi SQL HAVING queries

</aside>

```bash
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\W+\d*?\s*?having\s*?[^\s\-]" \
    "id:942251,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects HAVING injections',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/3',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl3=+%{tx.critical_anomaly_score}'"
```

## **Rule breakdown :**

<aside>
⚙ SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*

</aside>

This part specifies the variables that the rules is going to inspect

- REQUEST_COOKIES : Inspects all the cookies in the request
- !REQUEST_COOKIES:/__utm/ : Exclude the cookie with name __utm from the inspection
- REQUEST_COOKIES_NAMES : Inspect all the cookies names in the request
- ARGS_NAMES : Inspect all the arguments(parameters) names
- ARGS : Inspect all the arguments(parameters)
- XML: /* :  Inspect all elements of the XML payload if the request body is in XML

<aside>
⚙ "@rx (?i)\W+\d*?\s*?having\s*?[^\s\-]"

</aside>

This is the operator part it inspects the variables with a condition to be matched using regex @rx

- **`(?i)`**: Case-insensitive matching.
- **`\W+`**: Matches one or more non-word characters (e.g., spaces, punctuation).
- **`\d*?`**: Matches zero or more digits in a non-greedy manner.
- **`\s*?`**: Matches zero or more whitespace characters in a non-greedy manner.
- **`having`**: Matches the word `HAVING`, used in SQL queries to filter records after grouping.
- **`\s*?`**: Matches zero or more whitespace characters in a non-greedy manner.
- **`[^\s\-]`**: Matches any character that is not a whitespace or dash, ensuring that the `HAVING` clause is not immediately followed by a space or a dash.

<aside>
⚙ id:942251 : Specifies a unique id for the rule

</aside>

<aside>
⚙ phase:2 : specifies that the matching is done in the 2nd phase; the REQUEST_BODY phase

</aside>

<aside>
⚙ block : action to take if the rule matches

</aside>

<aside>
⚙ capture : captures matched mata for logging purposes

</aside>

<aside>
⚙

t: Transformation to apply to data before matching. t:none : resets transformations, t:urlDecodeUni :  decode URL-encoded characters, includes unicode encoding

</aside>

<aside>
⚙ msg:'Detects HAVING injections’

</aside>

<aside>
⚙ logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}’, Additional data to log if the rule matches, it includes the Matched Data  “%{TX.0}” ( this captures the exact part of the part that matched the regex pattern ) within the matched variable %{MATCHED_VAR_NAME}

</aside>

<aside>
⚙ tags

</aside>

- application-multi, language-multi, platform-multi : indicate that this rule is cross application,language and platform
- attack-sqli : indicates the rule is related to SQL injection
- paranoia-level/1: indicating that the paranoia level is 1
- OWASP_CRS , OWASP_CRS/WEB_ATTACK/SQL_INJECTION : indicates that the rule is part of the owasp core set rules used against SQL injections
- WASCTC/WASC-19 : Web Application Security Consortium threat classification for SQL injection
- OWASP_TOP_10/A1 : Owasp top 10 SQL injection category
- OWASP_AppSensor/CIE1 : OWASP AppSensor category for detecting injection attacks.
- PCI/6.5.2 : PCI DSS requirements for protecting web applications from SQL injections.

<aside>
⚙ ver:'OWASP_CRS/3.2.0’ : indicates the version of the owasp CRS this rule belongs to

</aside>

<aside>
⚙ severity:'CRITICAL’ :  Indicates the severity level of the rule if it matches

</aside>

<aside>
⚙ Score Adjustements

</aside>

- setvar: ‘ tx.sql_injection_score=+%{tx.critical_anomaly_score}’ : increases the ‘sql_injection_score’ transactional variable by the ‘tx.critical_anomaly_score’. for tracking the sql injection score which enables us to identify how severe and frequent SQL injections attempts and for action taking purposes when it arrives to a certain treshold.
- setvar:’tx.anomaly_score_pl3=+%{tx.critical_anomaly_score}’ : increases the transactional variable ‘tx.anomaly_score_pl3’ by ‘tx.critical_anomaly_score’, which helps track the anomay score in the paranoia level 3 and aids in actions taking purposes when it arrives to a certain treshold

## Isolation and Testing of this rule

/etc/modsecurity/rules/RULE3_PARANOIA_L3_Basic_SQL_Injection.conf

```sql
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\W+\d*?\s*?having\s*?[^\s\-]" \
    "id:942251,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects HAVING injections',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/3',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl3=+%{tx.critical_anomaly_score}'"
```

```bash
	vim /etc/apache2/mdos-enabled/security.conf # comment the inclusion of the other rules 
	# and include the testing rule
	
```

```bash
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier

        #IncludeOptional /etc/modsecurity/*.conf
        #Include /etc/modsecurity/rules/*.conf

        #including our testing rule
        #Include /etc/modsecurity/rules/RULE1_PARANOIA_L1_Basic_SQL_Injection.conf
				#Include /etc/modsecurity/rules/RULE2_PARANOIA_L2_Basic_SQL_Injection.conf
				Include /etc/modsecurity/rules/RULE3_PARANOIA_L3_Basic_SQL_Injection.conf
        #Include /etc/modsecurity/rules/RULE4_PARANOIA_L4_Basic_SQL_Injection.conf
        
        # Include OWASP ModSecurity CRS rules if installed
        #IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>

```

```bash
systemctl restart apache2
```

## Testing of the rule’s triggering

Check the apache error logs for incoming logs

```sql
tail -f /var/log/apache2/error.log
```

we test the following SQL injection payload inside the DVWA webserver trough the reverse proxy with the modsecurity WAF

```sql
1' UNION SELECT NULL, NULL, NULL HAVING '1'='1'
```

OR

```sql
1' OR 1=1 GROUP BY column1 HAVING COUNT(*) > 0#
```

OR

```sql
1%27%20HAVING%201%3D1-- 
```

<aside>
⛔ WAF successfully detects and blocks the attack (Payload successfully triggers the rule and increments the anomaly score by 5)

</aside>

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%208.png)

# Rule - Paranoia Level 4:

<aside>
💡 SQL Injection Character Anomaly Usage

</aside>

```bash
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES "@rx ((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>][^~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>]*?){3})" \
    "id:942421,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3)',\
    logdata:'Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/4',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'WARNING',\
    setvar:'tx.anomaly_score_pl4=+%{tx.warning_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.warning_anomaly_score}'"
```

## **Rule breakdown :**

<aside>
⚙ SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES

</aside>

This part specifies the variables that the rules is going to inspect

- REQUEST_COOKIES : Inspects all the cookies in the request
- !REQUEST_COOKIES:/__utm/ : Exclude the cookie with name __utm from the inspection
- !REQUEST_COOKIES:/_pk_ref/ : Exclude the cookie with name *pk_ref* from the inspection
- REQUEST_COOKIES_NAMES : Inspect all the cookies names in the request
- ARGS_NAMES : Inspect all the arguments(parameters) names
- ARGS : Inspect all the arguments(parameters)
- XML: /* :  Inspect all elements of the XML payload if the request body is in XML

<aside>
⚙ "@rx ((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>][^~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>]*?){3})"

</aside>

This is the operator part it inspects the variables with a condition to be matched using regex @rx

<aside>
⚙ id:942251 : Specifies a unique id for the rule

</aside>

<aside>
⚙ phase:2 : specifies that the matching is done in the 2nd phase; the REQUEST_BODY phase

</aside>

<aside>
⚙ block : action to take if the rule matches

</aside>

<aside>
⚙ capture : captures matched mata for logging purposes

</aside>

<aside>
⚙ t: Transformation to apply to data before matching. t:none : resets transformations, t:urlDecodeUni :  decode URL-encoded characters, includes unicode encoding

</aside>

<aside>
⚙ msg:'Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3)’

</aside>

<aside>
⚙ logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}’, Additional data to log if the rule matches, it includes the Matched Data  “%{TX.0}” ( this captures the exact part of the part that matched the regex pattern ) within the matched variable %{MATCHED_VAR_NAME}

</aside>

<aside>
⚙ tags

</aside>

- application-multi, language-multi, platform-multi : indicate that this rule is cross application,language and platform
- attack-sqli : indicates the rule is related to SQL injection
- paranoia-level/1: indicating that the paranoia level is 1
- OWASP_CRS , OWASP_CRS/WEB_ATTACK/SQL_INJECTION : indicates that the rule is part of the owasp core set rules used against SQL injections
- WASCTC/WASC-19 : Web Application Security Consortium threat classification for SQL injection
- OWASP_TOP_10/A1 : Owasp top 10 SQL injection category
- OWASP_AppSensor/CIE1 : OWASP AppSensor category for detecting injection attacks.
- PCI/6.5.2 : PCI DSS requirements for protecting web applications from SQL injections.

<aside>
⚙ ver:'OWASP_CRS/3.2.0’ : indicates the version of the owasp CRS this rule belongs to

</aside>

<aside>
⚙ severity:'WARNING’ :  Indicates the severity level of the rule if it matches

</aside>

<aside>
⚙ Score Adjustements

</aside>

- setvar: ‘ tx.sql_injection_score=+%{tx.critical_anomaly_score}’ : increases the ‘sql_injection_score’ transactional variable by the ‘tx.critical_anomaly_score’. for tracking the sql injection score which enables us to identify how severe and frequent SQL injections attempts and for action taking purposes when it arrives to a certain treshold.
- setvar:’tx.anomaly_score_pl4=+%{tx.critical_anomaly_score}’ : increases the transactional variable ‘tx.anomaly_score_pl4’ by ‘tx.critical_anomaly_score’, which helps track the anomay score in the paranoia level 4 and aids in actions taking purposes when it arrives to a certain treshold

## Isolation and Testing of this rule

/etc/modsecurity/rules/RULE4_PARANOIA_L4_Basic_SQL_Injection.conf

```sql
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES "@rx ((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>][^~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>]*?){3})" \
    "id:942421,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3)',\
    logdata:'Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/4',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'WARNING',\
    setvar:'tx.anomaly_score_pl4=+%{tx.warning_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.warning_anomaly_score}'"
```

```bash
	vim /etc/apache2/mdos-enabled/security.conf # comment the inclusion of the other rules 
	# and include the testing rule
```

```bash
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier

        #IncludeOptional /etc/modsecurity/*.conf
        #Include /etc/modsecurity/rules/*.conf

        #including our testing rule
        #Include /etc/modsecurity/rules/RULE1_PARANOIA_L1_Basic_SQL_Injection.conf
				#Include /etc/modsecurity/rules/RULE2_PARANOIA_L2_Basic_SQL_Injection.conf
				Include /etc/modsecurity/rules/RULE3_PARANOIA_L3_Basic_SQL_Injection.conf
        #Include /etc/modsecurity/rules/RULE4_PARANOIA_L4_Basic_SQL_Injection.conf
        
        # Include OWASP ModSecurity CRS rules if installed
        #IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>

```

```bash
systemctl restart apache2
```

## Testing of the rule’s triggering

Check the apache error logs for incoming logs

```sql
tail -f /var/log/apache2/error.log
```

we test the following SQL injection payload inside the DVWA webserver trough the reverse proxy with the modsecurity WAF

```sql
curl -i -X GET "http://192.168.235.132/" \
     -H "Cookie: test=1' OR 1=1; --"
```

<aside>
⛔ WAF successfully detects and blocks the attack (Payload successfully triggers the rule and increments the anomaly score by 3)

</aside>

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%209.png)

[Testing plan, and fine tuning :  REQUEST-942-APPLICATION-ATTACK-SQLI.conf](https://www.notion.so/Testing-plan-and-fine-tuning-REQUEST-942-APPLICATION-ATTACK-SQLI-conf-df3bbf0ac10446b08de63d9a7fa3eacd?pvs=21)

# Testing plan and fine tuning :  REQUEST-942-APPLICATION-ATTACK-SQLI.conf

# Exclude Non-SQLi rules

we excluce Non SQLi rules and only leave the SQLi rules and the files that are going to be used in Testing and Fine Tuning. therefore in the /etc/modsecurity/rules directory the only files are going to 

```sql
REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
REQUEST-901-INITIALIZATION.conf
REQUEST-942-APPLICATION-ATTACK-SQLI.conf
REQUEST-949-BLOCKING-EVALUATION.conf
RESPONSE-959-BLOCKING-EVALUATION.conf
RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
```

- REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf : allows you to exclude rules from being processed by CRS rules before they are applied - Runtime rule exclusion - to modify a rule at runtime it should be modified before its execution
- REQUEST-901-INITIALIZATION.conf : Includes rules for setting up environment and variables, like the inbound and outbound anomaly scores. the paranoia level and executing paranoia level….
- REQUEST-942-APPLICATION-ATTACK-SQLI.conf : Contains rules specific to SQL injection attacks
- REQUEST-949-BLOCKING-EVALUATION.conf : Evaluates request phase anomaly threshold, and decides whether to block if the configured threshold(on the crs-setup.conf file) is attained.
- RESPONSE-959-BLOCKING-EVALUATION.conf : Evaluates the response phase anomaly threshold, and decides whether to block if the configured threshold is attained
- RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf : allow you to add exclusion rules(remove…) after the CRS rules are applied - configure time - to remove a rule at configure time it should be first included

In the /etc/apache2/mods-enabled/security2.conf we include the rules folder :

```bash
IncludeOptional /etc/modsecurity/*.conf
Include /etc/modsecurity/rules/*.conf
```

I created a backup folder containing backup files :

```bash
REQUEST-942-APPLICATION-ATTACK-SQLI.conf.backup
REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.backup
RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.backup
```

## For monitoring and Logs :

<aside>
💡 /var/log/apache2/error.log is better for monitoring logs

</aside>

# Comprehensive Testing

Methodology : 

- **Blocking Paranoia Level**:
    - Determines which rules contribute to the anomaly score threshold.
    - Used to decide whether to block a request.
- **Executing Paranoia Level**:
    - Can be set higher than the blocking paranoia level.
    - Higher-level rules are executed but do not affect the blocking decision.
- **Example Setup**:
    - Blocking paranoia level: 1
    - Executing paranoia level: 2
    - Higher-level rules (level 2) are tested without blocking requests.
- **Benefits**:
    - Identifies and corrects false positives without blocking legitimate users.
    - Allows for safe and gradual increase of paranoia levels in production systems.

## Test

### Malicious payload:

```bash
1' UNION SELECT 0x757365726e616d65, 0x70617373776f7264 FROM users-- 
```

this SQL injection payload is equal to 1' UNION SELECT users, password from users —

### Benign(Non malicious) payload :

```bash
0x1234
```

## Analyzing Logs

There was no rule trigger for the previous benign payloads, until we raised the executing paranoia level to 2 where we get the following warnings (detections):

![Untitled](ModSecurity WAF and OWASP CRS project - Testing plan and fine tuning/Untitled%2010.png)

### The rules triggered by the payloads are :

First Rule - SQL Hex Evasion Methods : triggered by the first payload 0x1234

```bash
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i:\b0x[a-f\d]{3,})" \
    "id:942450,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Hex Encoding Identified',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/2',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

<aside>
📢 In order to remove false positives for these specific payloads we can use multiple methods.

</aside>

### 1st Method : Rule Exclusion by removing or updating the variables that caused that the false alarm from the rule

Example : 

Imagine a rule for which a parameter ID is giving false positives we can use Rule Exclusion by removing parameters(arguments) that caused that the false alarm from the rule

```bash
#RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
SecRuleUpdateTargetById 942450 “!ARGS:id”
```

<aside>
⛔ This method can be used, but according to the context

</aside>

### 2st Method : Regular Expression manipulation directly on the rule

Current regex for the first payload “0x1234”

```bash
(?i:\b0x[a-f\d]{3,})
```

This regex matches any hexadecimal number starting with `0x` followed by at least three hexadecimal characters. The `0x1234` payload triggered this rule.

Analysis:

- Legitimate cases might use hexadecimal values, especially in fields expecting hexadecimal input.
- We need to allow short hexadecimal numbers in benign contexts while still catching potentially harmful longer patterns often used in SQL injection.

Modified Regex:

To reduce false positives for this rule, we can adjust regex to be more specific to SQL injection patterns, for example we can add certain contexts (like specific SQL keywoard) around the hex patterns.

```bash
(?i:(?:\b0x[a-f\d]{3,}\b)(?:.*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|UNION|DROP)))
```

Updated Rule:

```bash
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i:(?:\b0x[a-f\d]{3,}\b)(?:.*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|UNION|DROP)))" \
    "id:942450,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Hex Encoding Identified',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/2',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

```

<aside>
✅ After a retest is done, no false alarms were produced this time

</aside>