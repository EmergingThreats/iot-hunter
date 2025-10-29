# IoT Hunter: A tool to make submitting rules to cover IoT vulns easier

This menu-driven python script records a number of options related to an IoT device vulnerability, and outputs both a Suricata rule **and** and Snort 2.9 rule that should meet ET style guide standards.

## Quickstart

1. Install python 3, if not already present
2. To use reference url archiving (optional), create an archive.org account 
3. Log in to archive.org, and navigate to https://archive.org/account/s3.php to retrieve the access key, and secret key for the wayback machine api
4. Clone this repohttps://github.com/da667/iot-hunter/edit/main/README.md
5. Enter the access and secret key on the line that begins with `wayback_machine_creds` (currently line 19)
6. run `IoT_hunter.py` and follow the prompts to generate a rule that hopefully meets your needs

## Detailed Guidance - Installation

1. Ensure that you have python 3.x installed on your system of choice. For debian-based distros, I recommend installing `python3-dev` and `python3-is-python` for maximum laziness.
2. Clone this repo.
3. The imports this script uses _should_ come standard with python3:
   
   ```
   argparse
   csv
   re
   textwrap
   os
   requests
   urllib3
   ```
   **Note**: Some users have noted that python venv/pipenv doesn't not include requests by default. It is suggested users confirm that they can run `import requests` if they choose to run in a virtual environment. If `requests` is not present, consider installing it to the virtual environment using `pip`.
   
4. To utilize the wayback machine archive option, users are recommended to enter their S3 Access and Secret keys into the script on line 19, as instructed.
   - If these creds are not entered, and the user requests archive of a url reference, they will be prompted to enther their Access/Secret key combination line.
   - The program will **not** detect whether or not the credentials **or** the format provided are valid. Please follow the instructions.
   - If invalid credentials are added, the script will still attempt to request an archive of the URL in question, note that this functionality is "best effort".

## Detailed Guidance: Supported Arguments

- `-i [/path/to/my.csv]`, `--infile [/path/to/my.csv]`
  - CSV input mode. Will automatically generate rules with as little manual input as possible. If a required CSV value is **not** present or **not** valid, and a default value is **not* assigned, program will fall back to manual input for the required value. For more information, please see: `Detailed Guidance: CSV Input` for all required and/or default values, and use the included CSV as a guide
- `-o [/path/to/my/output_file]`, `--outfile [/path/to/my/output_file]`
  - File output mode. Will output generated Suricata, and Snort rules to a text file of the users choosing. Utilizes append mode to avoid overwriting existing files, will **NOT** validate for duplicate sid values
- `-s [sid_number]`, `--sid_number [sid_number]`
  - Defines the sid number for the sid keyword. Iterates automatically with each newly generated rule. If no value is supplied, the default starting value is 1000000 (e.g.: `sid:1000000`, start of the local rule range). See also: sidallocation.org for more information about sid number ranges and how they are allocated.
- `-osu [/path/to/my/output_file]`, `--output-suricata [/path/to/my/output_file]`
  - Output Suricata rules **only** to the named file
- `-osn [/path/to/my/output_file]`, `--output-snort [/path/to/my/output_file]`
  - Output Completed Snort rules **only** to the named file
- `-opb [/path/to/my/output_file]`, `--output-proback [/path/to/my/output_file]`
  - Output proback-formatted Snort rules **only** to the named file

## Detailed Guidance: Manual Input

3. Run `IoT_hunter.py`
4. Follow the menu prompts:

### Vendor (and custom vendor)

- Enter the vendor associated with the vulnerability to properly fill out the `msg` keyword. The script offers a variety of common default entries:
  
  ```
  1: Asus
  2: D-Link
  3: Linksys
  4: Tenda
  5: Totolink
  6: TP-Link
  7: Other
  8: *Exit
  ```
  - **Note** most menu entries have a default setting that should be noted in the dialog. Additionally, the default option will have an asterisk (`*`) next to it. In this instance, the default is option 8, exiting the script. If the user hits the enter key without specifying a number, the script will exit.
  - If the user needs to enter a vendor name not on the list, option `7`, `Other` can be selected to manually input the vendor name. in an input prompt that follows.

### Reference URL

- The next input requires users to input their reference url, to be used with the `reference` keyword. Currently, this dialogue only supports url references.
- If the url begins with `http://`, `https://`, or `reference:url,` and/or ends with a semicolon (`;`), they are automatically stripped in order to be compatible with the `reference` keyword. 
- Users have the option of leaving this input blank, if there is no available url reference.

### Wayback Machine Archive

- If users have submitted a non-blank Reference URL, they will then be asked if they want to submit the url to internet archive's wayback machine for scraping. Options are:
  
  ```
  1: *No
  2: Yes
  ```

- To use this function, users will need to register an account on https://archive.org, and acquire their own S3 access key and secret key, which can be obtained on https://archive.org/account/s3.php

- Users will need to open the `IoT_hunter.py` script in a text editor, and enter their access key and secret key pair in the quotation marks on the line that reads:
  
  ```
  wayback_machine_creds= "[access_key]:[secret_key]"
  ```
  
  - Currently, as of version 3.0, this is line 19.
  - Replace the text `[access_key]` and `[secret_key]` with the appropriate values. 
    - **Do not** remove the colon (`:`) between the values.
    - **Do Not** remove the double quotes (`"`) surrounding the values.
  - If users choose yes, the API request is made with the following options:

- HTTP Headers:
  
  ```
  "User-Agent" : "IoT-Hunter"
  "Authorization" : "LOW [access_key]:[secret_key]
  "X-Accept-Reduced-Priority" : "1"
  ```

- HTTP Request body options:
  
  ```
  "url" : "https://[url entered for reference value]
  "capture_all" : "1"
  "delay_wb_availability" : "1"
  "skip_first_archive" : "1"
  "capture_outlinks" : "1"
  "capture_screenshot" : "1"
  ```

- **Note** This functionality is a "best effort" attempt to have the internet archive scrape the resource in question. There are many services that do not allow the wayback machine to scrape their pages and will result in errors.

### CVE number reference

- The next prompt asks users to enter a CVE number associated with the vulnerability, in the format: XXXX-XXXX. This is used to add a CVE number value to the `msg` keyword, and format another `reference` keyword with the CVE number
- If the input begins with `CVE-`, `cve-`, or reference:cve, and/or ends with a semicolon (`;`), that input is automatically stripped.
- If there is no CVE number assigned, users can hit Enter to continue with no CVE number associated with the `msg` or `reference` keywords in the rule that is created.

### HTTP Method

- Next, users will be prompted to select the http method to be used in the `http.method` sticky buffer's `content` keyword, and also determine if the vulnerable parameter will be located in the `http.uri` or `http.request_body` sticky buffer. Supported options are:
  
  ```
  1: *POST
  2: GET
  3: PUT
  4: PATCH
  5: HEAD
  6: DELETE
  ```

### URI Struct/Framework

- On the menu that follows, users are prompted to select the URI structure they want to use for their rule. This will form the `content` keyword in the `http.uri`  sticky buffer that will become the `fast_pattern` keyword for the produced rule (the exception being rules in which `/cgi-bin/cstecgi.cgi` is the chosen URI structure, which case, the `topicurl` parameter because the `fast_pattern` instead). Several IoT vendors re-use code designed to accept configuration changes for their products -- goform, boafrm, cstecgi.cgi, etc. This menu list includes those options, as well as an option for the user to input their own custom URI structure. Here is the menu:
  
  ```
  1: /boafrm/
  2: /goform/
  3: /cgi-bin/cstecgi.cgi
  4: *Custom URI
  ```

- **Note** If the vulnerability is a parameter in the http URI, users aren't expected to input the full URI plus the vulnerable parameter into the input box. For example, let's say the full URI is:
  
  - If options `1` or `2` are selected, the user is prompted to provide the "end" of the vulnerable URI. For example, if the complete vulnerable URI is:
    
    ```
    /boafrm/formPortFw
    ```

- Then the user would enter `formPortFw` (case sensitive).

- If users select option `3`, they will then be prompted to select a `topicurl` parameter value to serve as the `fast_pattern` for the generated rule.

- Option `4` allows users to supply a custom URI pattern not already covered by options `1-3`. For example ,let's say the full URI is:
  
  ```
  /ayy/lmao/1.php?a=1&b=2&c=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  ```

- Users would input `/ayy/lmao/1.php?` as the vulnerable URI. **do not** supply **any** of the URI query parameters past the question mark (`?`), Even if the vulnerability is in a GET or HEAD request. **Users will enter the vulnerable URI parameter in a separate prompt that follows**.

- **Note** the script automatically converts any trailing question mark characters (`?`) to `|3f|`, Suricata/Snort's hex escape format for content matches.

- **Note** the script also extracts the "end" of the submitted URI (between the last forward slash (`/`), and the first question mark (`?`) to input into the `msg` keyword (e.g., the `msg` for this URI would contain "1.php")

### Parameter Location

- If the the http method is set to `DELETE`, then after selecting the method and URI structure, the user will be asked to determine where the vulnerable parameter is located, with two choices available:
  
  ```
  1 : *Client Request Body
  2 : URI
  ```
- In most other cases, the location of the vulnerable parameter is assumed:
  - `GET` or `HEAD` requests: URI
  - `POST`, `PUT`, or `PATCH` requests: Client Request Body
  - With `DELETE` requests, there is the possibility that a vulnerable parameter could be either in the URI or Client Request Body, so users are asked to choose.

### Parameter type

- The next menu asks for the format of the vulnerable parameter if the vulnerability is in a POST, PUT, PATCH, or DELETE request (that the user has indicated has parameters in the client body)  request. Valid choices are:
  
  ```
  1: *Equal sign (=) Key/Value pairs
  2: JSON  Key/Value pairs
  ```
- If `GET` or `HEAD` are the `http_method` for the rule, then Equal sign delimited paramter is chosen by default.

### Vulnerable Parameter NAme

- Next, the user is required to enter the vulnerable parameter. Currently, this script supports **only one** vulnerable parameter. 
  - If the parameter is in the HTTP_URI, the only valid choice is an equal sign Key/Value pair (e.g., foo=baz)
  - If the uri structure is `/cgi-bin/cstecgi.cgi`, then the only valid choice for parameter type (and location) is the request body.
- Going back to the previous example URI:
  
  ```
  /ayy/lmao/1.php?a=1&b=2&c=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  ```
- Parameter `c` is the vulnerable parameter that is being targeted with a buffer overflow. Users should input `c=` for the vulnerable parameter
- Likewise, if the vulnerability is in a JSON formatted parameter in the request body, Users should input `"c"` as the vulnerable parameter, assuming the data is formatted like:
  
  ```
  {"c":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
  ```
- If users forget to format the vulnerable parameter correctly (e.g., enter just `c` instead of `c=`, or just `c`, instead of `"c"`, then the script will automatically add double quotes, around the parameter if JSON `POST/PUT/PATCH/DELETE` data, or an equal sign to the end of the parameter, if the parameter is equal sign delimited in either the `POST/PUT/PATCH/DELETE` body, or HTTP URI in a `GET` or `HEAD` request.

### `topicurl` Value

- If users selected `/cgi-bin/cstecgi.cgi` as their URL and an HTTP method that allows for client body data, (`POST, PUT, PATCH, DELETE`), users will be asked to enter the `topicurl` parameter value. Devices that use this web framework for managing devices (primarily Totolink branded devices), use this client body parameter to determine what functionality that the rest of the post body data applies to.

### `pcre` content selection, vulnerability `msg` description, `classtype` selection

- Finally users are prompted to select the type of vulnerability they wish to cover with their rule. This menu option formats the rule `msg` keyword, and selects One of five `pcre` keywords and regular expressions for use in the generated rule, and populates an appropriate `classtype` keyword. Valid choices are:
  
  ```
  1: *Buffer Overflow
  2: Command Injection
  3: Cross Site Scripting
  4: Directory Traversal
  5: SQL Injection
  6: Custom PCRE, Custom Vulnerability Type, Custom classtype
  7: No PCRE, Custom Vulnerability Type, Custom classtype
  ```
- The regular expressions used for options one through five are based on regular expressions developed by the STX team that have seen wide use in the ET ruleset, and are very effective:

#### Common Directory Traversal PCRE:

`pcre:"/^[^\x26]*?(?:(?:\x2e|%2[Ee]){1,2}(?:\x2f|\x5c|%5[Cc]|%2[Ff]){1,}){2,}/R";`

##### Common Directory Traversal PCRE, with JSON Key/Value Pairs:

`pcre:"/^(?:\x3a(?:\x20\x22|\x22) )?[^\x2c\x7d$]*?(?:(?:\x2e|%2[Ee]){1,2}(?:\x2f|\x5c|%5[Cc]|%2[Ff]){1,}){2,}/R"`

#### Common Command Injection PCRE:

`pcre:"/^[^\x26]*?(?:(?:\x3b|%3[Bb])|(?:\x0a|%0[Aa])|(?:\x60|%60)|(?:\x7c|%7[Cc])|(?:\x24|%24))+/R";`

##### Common Command Injection PCRE, with JSON Key/Value Pairs:

`pcre:/^(?:\x3a(?:\x20\x22|\x22))?[^\x2c\x7d$]*?(?:(?:\x3b|%3[Bb])|(?:\x0a|%0[Aa])|(?:\x60|%60)|(?:\x7c|%7[Cc])|(?:\x24|%24))+/R`

#### Buffer overflow PCRE:

`pcre:"/^[^&]{100,}(?:&|$)/R";`

##### Buffer overflow PCRE, with JSON Key/Value pairs:

`pcre:"/^(?:\x3a(?:\x20\x22|\x22))?[^\x2c\x7d$]{100,}(?:,|}|$)/R";`

#### SQL Inject PCRE:

`pcre:"/^[^<]*?(?:'|%27|-{2}|%2d%2d)?(?:(?:S(?:HOW.+(?:C(?:UR(?:DAT|TIM)E|HARACTER.+SET)|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER|SLEEP|CONCAT|CASE))|U(?:NION SELEC|PDATE.+SE)T|DELETE.+FROM|INSERT.+INTO)|S(?:HOW.+(?:C(?:HARACTER.+SET|UR(DATE|TIME))|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER))|U(?:NION.+SELEC|PDATE.+SE)T|(?:NULL(?:,|%2[cC])){2,}|(?:/|%2[fF])(?:*|%2[aA]).+(?:*|%2[aA]).+(?:/|%2[fF])|CONCAT.+SELECT|EXTRACTVALUE|UNION.+ALL)/Ri";`

#### XSS PCRE:

`pcre:"/^.*(?:on(?:(?:error)|(?:s(?:elec|ubmi)|rese)t|d(?:blclick|ragdrop)|(?:mouse|key)[a-z]|c(?:hange|lick)|(?:un)?load|focus|blur)|s(?:cript|tyle))(?:=|%3[dD])?/Ri";`

- Options `1` through `5` will automatically apply the following string to the `msg` keyword:
  
  ```
  1 : Buffer Overflow Attempt
  2 : Command Injection Attempt
  3 : Cross Site Scripting Attempt
  4 : Directory Traversal Attempt
  5 : SQL Injection Attempt
  ```
- Options `1` through `5` will also automatically apply the following `classtype` values:
  
  ```
  1 : web-application-attack
  2 : attempted-admin
  3 : web-application-attack
  4 : attempted-admin
  5 : web-application-attack
  ```
- Selecting option `6` will require the user to:
  - Manually enter a regular expression. The user will have to enter the entire expression (from the first `/` to the final `/`), including the modifier (e.g. `/R` for relative, `/U` for uri, `/P` for client body, etc.)
    - For example, to search for the string "ayylmao" at anypoint AFTER the content match, bounding the search to be RELATIVE from the previous content match, the user would need to input:
      
      ```
      /.*?ayylmao/R
      ```
  - Note the `/` at the start and end of the expression, and the `R` modifier after the final `/`
  - **Note**: `\x` hex-encoded values will need to have their leading backslash character commented out (e.g., `\\x`)
  - Manually enter the type of vulnerability that should be portrayed in the alert message. For example:
    
    ```
    Attempted Information Leak
    ```
  - Manually enter a valid classtype value present in their `classification.config` file. For example
    
    ```
    attempted-recon
    ```

- Selecting option `7` is nearly identical to option `6`. The primary difference is that users are not prompted to enter a regular expression, and there is no regular expression or `pcre` keyword present in the rule.

### Expected inputs and outputs

- Upon following the menu prompts a rule is generated.
- Example inputs:
  
  ```
  Vendor: Asus
  HTTP Method: POST
  URI Struct: /ayy/lmao/1.php?
  URL reference: https://www.example.com
  Submit to Internet Archive: No
  CVE Number: 1111-1111
  Type of Parameter: Equal sign delimited
  Parameter: c
  Vulnerability type: Buffer Overflow
  ```
- Example output:
  
  ```
  alert http any any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Asus 1.php c Parameter Buffer Overflow Attempt (CVE-1111-1111)"; flow:established,to_server; http.method; content:"POST"; http.uri; bsize:19; content:"/ayy/lmao/1.php|3f|"; fast_pattern; http.request_body; content:"c|3d|"; pcre:"/^[^&]{100,}(?:&|$)/R"; reference:url,www.example.com; reference:cve,1111-1111; classtype:attempted-admin sid:1; rev:1;)
  ```

## CSV Input Mode Quick Guide

### Column names

| vendor | vendor_custom | reference_url | wbm_archive | reference_cve | http_meth | uri_struct | uri_struct_end | uri_struct_custom | param_loc | uri_parameter | p_body_param_type | p_body_param | topicurl | vuln_type | custom_pcre | custom_vulntype | custom_classtype | Notes |

#### Value Types:

`vendor`: int 1 - 7

- `1` = Asus
- `2` = D-Link
- `3` = Linksys
- `4` = Tenda
- `5` = Totolink
- `6` = TP-Link
- `7` = Custom value
  Default: `1` 

`vendor_custom`: string

`reference_url`: string

- not required

`wbm_archive` : int value, 1 - 2

- `1` = Don't Archive
- `2` = Attempt to Archive
  Default: `1`

`reference_cve`: string

- not required

`http_meth`: int value, 1 - 6

- `1` = POST
- `2` = GET
- `3` = PUT
- `4` = PATCH
- `5` = HEAD
- `6` = DELETE
  Default: `1`

`uri_struct`: int value, 1 - 4

- `1` = /boafrm/
- `2` = /goform
- `3` = /cgi-bin/cstecgi.cgi
- `4` = Custom URI

`uri_struct_end`: string

- only necessary if `uri_struct` set to `1` or `2`

`uri_struct_custom`: string

- only necessary if `uri_struct` set to `4`
- string from the first `/` to the first `?` IF the URI includes query strings

`param_loc`: int value, 1 - 2

- only necessary if `http_meth` set to `6` (DELETE)
  - `1` = Client Request Body
  - `2` = URI
    Default: `1`

`uri_parameter`: string

- Only needs to be set if `http_meth` is set to `2` or `5` (GET or HEAD)
- ends with equal sign (`=`) If equal sign not in value, it will automatically be appended.

`p_body_param_type`: int value, 1 - 2

- `1` = Equal Sign (`=`) Key/Value Pair
- `2` = JSON Key/Value pair
  Default: 1

`p_body_param`: string

- Only needs to be set if `http_meth` is set to `1`, `3`, `4` or `6` (`6` only of `param_loc` is set to `1`)
- Required if `uri_struct` is set to `3`

`topicurl`: string

- Required if `uri_struct` is set to `3`

`vuln_type`: int value, 1 - 7

- `1` = Buffer Overflow
- `2` = Command Injection
- `3` = Cross Site Scripting
- `4` = Directory Traversal
- `5` = SQL Injection
- `6` = Custom PCRE, Custom Vulnerability Type, Custom classtype
- `7` = No PCRE, Custom Vulnerability Type, Custom classtype
  - Values `1` - `5` automatically set `pcre`, `msg`, `classtype`

`custom_pcre`: string

- Required if `vuln_type` set to `6` or `7`

`custom_vulntype`: string

- Required if `vuln_type` set to `6` or `7`

`custom_classtype`: string

- Required if `vuln_type` set to `6` or `7`

`Notes`: string 

- not parsed, for user utilization only

## Detailed Guidance: CSV input/Automated mode

- CSV input mode, as documented in the `Detailed Guidance: Supported Arguments` is invoked with the `-i` or `--infile` argument, along with a directory path to the CSV file to parse
- If a value is unable to be parsed from the provided CSV, default values will be utilized (where applicable) instead, or if there is no viable default value, the user will be prompted to input a value manually or stop the program, and fix the provided CSV
- The included sample CSV file includes 19 values, of which 18 are used (The `Notes` column is not parsed or used). The purpose, acceptable values, and default values (where appropriate) the various fields will be defined below:

### CSV Column names and acceptable values

#### vendor

- `vendor` has 7 valid numeric integer values, numbered `1` through `7`:
  - `1` = Asus
  - `2` = D-Link
  - `3` = Linksys
  - `4` = Tenda
  - `5` = Totolink
  - `6` = TP-Link
  - `7` = Custom value (see: `vendor_custom`)
  - If no value is present in the CSV file, the user will be prompted to provide a valid integer value between `1` and `8`
  - While technically valid, option `8` exits the program

#### vendor_custom

- `vendor_custom` is only required to be filled out if users enter option `7` as the value for `vendor`. This field allows users to specify a custom vendor name for the `msg` keyword of the rule 
  - For example: if users wanted to input `ABB Cylon Aspect`:
  - Input option `7` in the `vendor` column, then in the `vendor_custom` column, enter `ABB Cylon Aspect`
  - For another example, if users wish to specify a vulnerability in D-Link products, but wanted to include a specific hardware model and/or version strings along side the vendor name (e.g., `D-Link DIR-846 Firmware DIR846enFW100A53DBR-Retail` (https://www.exploit-db.com/exploits/51243)) :
  - Input option `7` in the `vendor` column, then in the `vendor_custom` column, enter `D-Link DIR-846 Firmware DIR846enFW100A53DBR-Retail`
  - If users specify option `7` in the `vendor` column, and the `vendor_custom` column is blank, or there is an exception, the program will require the user to manually enter the desired value for `vendor_custom`

#### reference_url

- `reference_url` defines a url users wish to include in the `reference` keyword metadata for their rule
  - The program does **NOT** perform any validation against values entered into the `reference_url` column
  - URLs may begin with `http://`, `https://`, `reference:url,` or the just the domain name (or IP address) with the application URI without the protocol specifier.
  - The `reference:url` keyword specification requires that the protocol specifier (e.g. `http://` or `https://`) be removed, leaving only the domain. This program will strip the `http://` or `https://` protocol specifier automatically.
  - Other protocol specifiers are **NOT** supported at this time
  - example: `https://www.exploit-db.com/exploits/51243`
    - may be entered as:
    - `https://www.exploit-db.com/exploits/51243`
    - `http://www.exploit-db.com/exploits/51243` (If the site supports only HTTP or supports automatic upgrade from HTTP to HTTPS)
    - `reference:url,www.exploit-db.com/exploits/51243;` (e.g., copied reference value from an existing Snort or Suricata rule)
    - `www.exploit-db.com/exploits/51243`
    - All four of these input values will result in `reference:url,www.exploit-db.com/exploits/51243;`
  - If the value ends with a semicolon (`;`) (for example, a `reference` keyword from an existing rule) the semicolon will automatically be stripped from the end of the input string
  - Blank values are acceptable. In which case no `reference:url` keyword value will be supplied with the generated rule, and the program **WILL NOT** prompt the user for input

#### wbm_archive

- `wbm_archive` defines whether or not the normalized `reference_url` field will be submitted to the internet archive's wayback machine for archival purposes to protect proof-of-concept code from being lost, deleted or otherwise unavailable for recovery later
  - Valid values include:
  - `1` (Don't Archive)
  - `2` (Submit to the wayback machine to atttempt to archive)
  - If no value is provided, or the value provided is invalid, the program defaults to **NOT** submitting the `reference_url` to the wayback machine for archiving
  - If the `reference_url` value is blank, the archive request functionality is skipped entirely
  - If the `wayback_machine_creds` value is blank, or the default value **and** `wbm_archive` is set to `2`, the script will prompt users, asking them if they wish to enter their wayback machine API credentials 
  - Selecting option `1` (or hitting the enter key with zero input) will cancel the attempt to archive the `reference_url` value
  - Selecting option `2` will prompt users to input their wayback machine api credentials
    - The input provided to the program for option `2` **Cannot be blank**
  - The program will ask the user if they wish to enter their credentials to the wayback machine API **for each and every rule submitted, if `wbm_archive` is set to `2`, and no credentials are supplied**. See the `Quickstart`, or `Detailed Guidance - Manual Input` portions of the documentation for further guidance on how to set this value in the program, and no longer be prompted
  - Archival requests are a "best effort" attempt. Meaning that adversarial measures (e.g. proof-of-work, anti-AI, robots.txt, noindex/nofollow HTML metatags, "Turnstiles", CAPTCHAs, etc.) will all prevent the site from being archived.
  - Archival requests are submitted to the wayback machine under LOW priority, along with the `X-Accept-Reduced-Priority` header set to `1`. This sometimes results in the wayback machine API responding to archive requests confirming reciept, but informing the user the site requested will be added to an archive queue for later retrieval
  - Additionally if invalid API credentials are submitted, sites may not be archived correctly (e.g., no screen capture, and no outlinks captured)

#### reference_cve

- `reference_cve` defines a CVE number users with to include in the `reference` keyword metadata for their rule, and also defines a CVE number appended to the end of the `msg` keyword
  - The program does **NOT** perform any validation against the values entered into the `reference_cve` column
  - CVE numbers may begin with:
  - `CVE-`
  - `cve-`
  - or just the actual CVE number itself.
    - For example: CVE-2022-46552 Can be entered as:
    - `CVE-2022-46552`
    - `cve-2022-46552`
    - `reference:cve,2022-46552;` (e.g., copied `reference` keyword from an existing rule)
    - `2022-46552`
    - All four of these values will result in:
    - `(CVE-2022-46552)` appended to the end of the `msg` keyword
    - `reference:cve,2022-46552;` as a `reference` keyword
- If the CVE Number input ends with a semicolon (;) it is automatically stripped
- Blank values are acceptable. In which case no `reference:cve` keyword value will be supplied to the generated rule. Additionally the rule `msg` keyword will not end with a CVE number, either

#### http_meth

- The `http_meth` value determines what content match will be placed into the `http.method` Suricata sticky buffer (and/or Snort's `http_method;` content modifier). 
- `http_meth` can be a numeric integer value between `1` and `6`:
  
  ```
  1 = POST
  2 = GET
  3 = PUT
  4 = PATCH
  5 = HEAD
  6 = DELETE
  ```
- Additional http methods are **NOT** supported at this time.
- If no value is selected for the `http_meth` column, the default value is option `1` (POST)

#### uri_struct

- Determines the value that will be placed in the content matches located in the suricata `http.uri` sticky buffer (and/or Snort's 'http_method;' content modifier).
- Accepts numeric integer values between `1` and `4`:
  
  ```
  1 = /boafrm/
  2 = /goform
  3 = /cgi-bin/cstecgi.cgi
  4 = Custom URI
  ```
- If the value is blank, or otherwise invalid, the program will prompt the user for valid input out of the choices listed above.
- If option `1` or `2` are selected then the `uri_struct_end` column **must** be filled out.=
- option `3` cannot be combined with `HEAD` or `GET` requests
- IF option `4` is selected, the user must fill in the `uri_struct_custom` field 

#### uri_struct_end

- If options `1` or `2` are selected for the `uri_struct` column, then this column **must** be filled
- There is no default value.=
- If the value in this column is blank or otherwise invalid, users will be prompted to enter a value.=
- For example, if the user wanted to write a rule for the URI `/boafrm/submitExampleValue`
  - They would input option `1` for the `uri_struct` column (`/boafrm`)
  - Then for the `uri_struct_end` value, they would input the text `submitExampleValue`

#### uri_struct_custom

- If option `4` was selected for the `uri_struct` value, then this value **must** be filled out
- Input the vulnerable URI.
- If the URI includes query parameters, only input the URI value from the first forward slash (`/`) to the first question mark (`?`).
  - For example, if the URI is `/ayy/lmao/1.cfm?a=1&b=2&c=%60cat%20%2fetc%2fpasswd%60`:
  - Input `/ayy/lmao/1.cfm?` as the `uri_struct_custom` value

#### param_loc

- If the user utilizes `DELETE` as the value for the `http_meth` column, they will need to fill in the `param_loc` field as well
- `param_loc` defines where the vulnerable parameter for the generated rule can be found
- Accepts numeric integer values `1` or `2`:
  
  ```
  1 = Client Request Body
  2 = URI
  ```
- If no value is provided, or the value is otherwise invalid, the program defaults to option `1` (Client Request Body)
- If the `http_meth` is `GET` or `HEAD` the parameter is assumed to be in the HTTP URI
- If the `http_meth` is `POST`, `PUT` or `PATCH`, the parameter is assumed to be in the http client body

#### uri_parameter

- If the user has specified that the `http_meth` value is `GET`, `HEAD` or `DELETE` (with `param_loc` set to `2`), this value **must** be filled out
- If `uri_struct` is set to option `3` (`/cgi-bin/cstecgi.cgi`) then the parameter will **never** be a URI parameter, and is not allowed
- If left blank, or otherwise invalid, users will be prompted to enter the vulnerable URI parameter manually
- If the value does not end with an equal sign, a hex-escaped equal sign (e.g., |3d|) will automatically be appended to the end of the parameter's content keyword

#### p_body_param_type

- If the user has specified that the `http_meth` value is `POST`, `PUT`, `PATCH`, or `DELETE` (with `param_loc` set to `1`), this value must be filled out
- Accepts numeric integer values `1` or `2`:
  
  ```
  1 = *Equal sign (=) Key/Value pair (e.g., vuln=aaaaaaaaaaaaaaaaaa)
  2 = JSON  Key/Value pair (e.g., "vuln":"aaaaaaaaaaaaaaaa")
  ```
- If left blank, or the choice is otherwise invalid, the default value of `1` (Equal Sign (`=`) Key/Value pair) will be selected

#### p_body_param

- If the user has specified that the `http_meth` value is `POST`, `PUT`, `PATCH`, or `DELETE` (with `param_loc` set to `1`), or if the `uri_struct` value is set to `3`, this value **must** be filled out
- If left blank, or otherwise invalid, users will be prompted to enter the vulnerable http request body parameter that will be used to form the content keyword of the vulnerable parameter in the `http.request_body` sticky buffer (and/or Snort's `http_client_body` content modifier)

#### topicurl

- this defines the value of the topicurl parameter, frequently used in combination with `/cgi-bin/cstecgi.cgi`
- If the user set the `uri_struct` value to `3`, then this value must be filled out, as it will serve as the `fast_pattern` for the rule generated
- If left blank, or otherwise invalid, users will be prompoted to enter the topicurl parameter's value manually

#### vuln_type

- Defines the type of vulnerability the generated rule is meant to detect
- This field defines the content of the `msg` keyword, the `pcre` keyword (if there is a PCRE keyword at all), and the `classtype` keyword
- This field accepts numeric integer values between `1` and `7`:
  
  ```
  1 = Buffer Overflow
  2 = Command Injection
  3 = Cross Site Scripting
  4 = Directory Traversal
  5 = SQL Injection
  6 = Custom PCRE, Custom Vulnerability Type, Custom classtype
  7 = No PCRE, Custom Vulnerability Type, Custom classtype
  ```
- If left blank, or otherwise invalid, the default value of `1` will be used
- If option `6` is selected, the values `custom_pcre`, `custom_vulntype`, and `custom_classtype` must **all** be filled out
- If option `7` is selected, then only the values `custom_vulntype`, and `custom_classtype` **must** be filled out

#### custom_pcre

- If option `6` in the `vuln_type` column is selected, Value must be filled out with a regular expression value, complete with beginning forward slash (`/`) and ending forward slash (`/`) along with any modifiers (e.g. `R` for "relative")
- For example: to search for the string "ayylmao" relative to the vulnerabile parameter (`/R`) with any number of characters in between the regular expression `/.*?ayylmao/R` can be placed into the `custom_pcre` field
- If left blank, or the value is otherwise invalid, users will be required to manually enter the desired regular expression.
- **Note** backslashes are **required** to be commented out. (e.g. `\x20` would need to become `\\x20` instead)

#### custom_vulntype

- This value defines the vulnerability message portrayed in the `msg` keyword.
- This value is placed in the `msg` keyword after the vulnable URI endpoint, and vulnerable parameter, and before the CVE number, if any have been specified.
- Example:
  
  ```
  Information Leak Attempt
  ```
- Results in:
  
  ```
  msg:"ET WEB_SPECIFIC_APPS example.php ayy Parameter Information Leak Attempt (CVE-1111-1111)";
  ```
- If option `6` or option `7` were selected for the `vuln_type` field, this value **must** be filled out
- If left blank, or the value is otherwise invalid, the user will be prompted to enter the vulnerabilty string manually.

#### custom_classtype

- This value defines the `classtype` keyword for the generated rule.
- If option `6` or option `7` were selected for the `vuln_type` field, this value **must** be filled out
- If left blank, or the value is otherwise invalid, the user will be prompted to enter the classtype string manually.
- This program does **not** validate the classtype string against a `classification.config` file. 
- Users are advised to refer to the `classification.config` file used for their Snort or Suricata deployment for valid values.
- Example input:
  
  ```
  attempted-recon
  ```
- Result:
  
  ```
  classtype:attempted-recon;
  ```

#### Notes

- May be used to document any notes relevant to the rule that will be generated from the values in this row.
- Value is not parsed or utilized by `IOT_hunter.py` in any way.

# Patch Notes:

- 20 August 2025
  - Ran into a problem where python `requests` had problems verifying the SSL certificate for the internet archive site we hit to request scraping the reference. Fixed this via `try/catch` on `requests.exceptions.SSLError`. If the first request throws an SSLError, then we make the same request again, set `verify=False`, and also suppression SSL certificate verification warnings
  - Noticed that in my short-sightedness, that for IoT rules for platforms that utilize `/cgi-bin/cstecgi.cgi`, that we're not making use of the `"topicurl"` JSON element. this element defines what page/function the vulnerability belongs to, so it makes sense to utilize _that_ as the `fast_pattern`, instead of the unchanging `cstecgi.cgi` URI instead
- 22 August 2025
  - 2.0.0 "Sectoid" release
  - Integrates automated conversion of Suricata 5 rules to Snort 2.9
    - Two formats: 
    - Plain formatting in which rule metadata is still present, and the output rule is a fully formed Snort rule
    - Proback formatting, stripping all metadata from the rule (`msg`, `reference`, `classtype`, `sid`, `rev`, and `metadata` keywords), core detection logic and rule header only
  - The new rule formats each have a header, that will be printed with the terminal output in green text to differentiate which rule type is which (`suricata`, `snort, plain`, `snort, proback`)
- 27 August 2025
  - 3.0.0 "Thin Man" release
  - Argument parsing, and the following arguments have been added:
  - `-i` CSV file input
  - `-o` output file for newly generate snort and suricata rules
  - `-s` starting sid number. Iterates with each new rule. Default value is 1000000
  - CSV input support has been added. Documentation on field names, valid values, and a sample document containing a variety of examples will have been added to this repo
  - CSV input has tons of exception-handling. In certain cases (where I was feeling lazy), default values are applied, in the event that the value/column of the CSV file necessary is unreadable, or blank
  - In other cases, if CSV input fails to read a value, or if its blank, the user will be prompted to fill in the required value, and fix their CSV file
  - Alternatively, users can hit Ctrl+C to stop the script, edit their CSV file, and try again
  - If the user has requested the reference url be archived via the internet archive's "wayback machine", but they have NOT supplied the wayback machine S3 API credentials
- 2 September 2025
  - 3.1.0 "ShieldBearer" release
  - New output aguments provided:
    -`-osu`, `--output-suricata` = Output Suricata rules **only** to the named file
    -`-osn`, `--output-snort` = Output Completed Snort rules **only** to the named file
    -`-opb`, `--output-proback` = Output proback-formatted Snort rules **only** to the named file
  - sample_files directory created
  - includes a CSV file with three valid, real-world vulnerabilities with "all of the necessary parameters" to write rules for them included
  - also includes sample output in `-o`, `-osu`, `-osn`, and `-opb` file output formats.
- 11 September 2025
  - 3.2.0 "Viper" release
  - the `metadata` keyword, and several tags have been applied to all rules IoT_hunter generates
    - the metadata tags are static, and based on the type of vulnerability/pcre used to generate a given rule
    - all rules have the following tags:
      - affected_product
        - value: the value of the vendor name
      - tls_state
        - value: plaintext
      - created_at
        - value: YYYY_MM_DD
      - cve
        - value: cve number refence data (if filled out, not present if not filled out)
      - deployment
        - value: Perimeter, Internal
      - confidence
        - value: High
      - signature_severity
        - value: Major
    - Rules with a statically defined regular expression and vulnerability type also have:
      - `mitre_tactic_id`, `mitre_tactic_name`, `mitre_technique_id` and `mitre_technique_name`
    - all tags in the `metadata` keyword are statically generated. 
    - Users may add, delete, or modify metadata key/value pairs manually if the tags defined are not sufficient, or incorrect
  - the `target` keyword, with the setting `dest_ip`
    - the `target` tag is correctly removed from generated snort rules.
- 26 September 2025
  - 3.2.1 "Boa" release
    - Additional musketeer binding added in order to prepare for scope expansion into DNS, TLS cert, and TLS SNI rule generation (possibly)
    - `pylint`'ed 3,000+ lines of code manually. While I ignored a lot of frivilous things, a lot of the code has been cleaned up and modernized.
    - New sample files showing metadata outputs for snort and suricata rules (proback format rules remain unchanged)
- 1 October 2025
  - 3.2.2 "Sidewinder" release
    - Fixed an infinite loop problem in option 6, for pcre choices. Whoopsie.
- 29 October 2025
  - 3.2.3 "Naga" release
    - Fixed issues #3, #5, and #6
	- #3 docbug - `venv` and `pipenv` sometimes do not include requests. Users may need to use `pip` to install `requests`.
	- #5 NameError - rule_loop_pcre arg 5 (SQLi) was attempted to return the wrong variable name.
	- #6 SQLi Regex Compilation - certain special characters to `pcre2` regular expressions were not properly being escaped in the SQL Injection regex of rule_loop_pcre. The regex compilation has since been corrected.