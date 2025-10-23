# 1PassMapper

## Why? 

This is a security thing, where you want to keep your credentials out of your git files 
but when you deploy, you need to build the credentials and stick them into configuration 
files that goes into for example, your docker docker container. 

You want to keep a copy of the configuration template showing the base configuration and 
everything as it should be, but you do not want to keep the actual credentials inside the file.

Also, when you update the credentials, you want them to update inside your build process,  
and regardless of where you build, you can reuse the same objects by using different paths 
inside the source file and it will update everywhere.

This is where 1PassMapper comes in. 

It takes a credentials file which can be a local JSON object containing your credentials 
or a similar file stored inside a 1Password item in the field `json`. 
it will then take your template file and replace all the tags inside with the real data from 
the 1Password service, or your credentials JSON file.

This lets you keep the template configuration files inside git and have for example the password 
being stored as a tag instead of the real value, and this also implies that you can have different 
sources for the same configuration file using for example environment as a differentiator.

The format of the JSON source file is the same whether it's stored in the local file or 
inside the JSON field in 1Password. 

## Changelog

```plain text
1.3.0   2025-10-23  Added support for type prefix in paths. 
1.2.0   2025-10-23  Added support for multiple 1Pass source items, 
                    allowing the use of multiple 1pass items to be applied in 1 pass.    
1.1.0   2025-09-10  Added support for `-prefix`
1.0.0               Original release
```

## Application prerequisite

The Onepass CLI app must be installed on the machine. 


## 1Password config & setup

1. Create an app token on 1Password.
2. Create the file ~/.1passtoken, and store the token in this file. 
3. Create a vault, preferably as a name without spaces, like "CICD".
4. Create an item, preferably as a name without spaces, like "MySecretCollection".
5. In the item, create a field called "json", and save the JSON data in this field. 

## Input parameters to the application

    Usage of 1PassMapper:
    
    -v                  Increase the verbosity to show what tags are translated or not.
    -vv                 INSECURE!! Increase the verbosity to show what tags are translated or not, adding the value replacing the tag. (only use for debug!)
    -prefix     string  The prefix to use for all paths (default: ""), such as "dev" or other dot-notation path prefix. 
    -tokenfile  string  The name of the 1pass token file to use, if different from teh default (~/.1passtoken)  
    -injson     string  Input JSON source file in case you do not want to use 1Password
                        Supplying this option will bypass the use of 1Password, and use the file 
                        as source of credentials. 
    
    -in         string  Input file path - eg. "my-config-template.json"
    -out        string  Output file path - eg. "config.json"
    -vault      string  1Password vault name - eg. "CICD"
    -item       string  1Password item name or names (name1,name2,...) (source of JSON) - eg. "MySecretCollection"
    -token      string  1Password Service Account token (optional; if empty, read from ~/.1passtoken)
    -V                  Display version.

## Tags - How they are designed and works

Note that the `sample–template.json` below can be any file or type of text format document not just confined to JSON, 
allowing this solution would equally well apply to plain text documents, yml or any other kind of text-based documents.

The important part is the tags that will be used to replace them, as they are placeholders.

The format is simple - All tags starts with a `[[` and ends with a `]]`, and what is inside, is the json path to the value.

The format with double `[[...]]` has been deliberately chosen not to conflict with CSS, JSON, or JavaScript and many other formats or languages.

Please note that the -prefix <path>, will prepend the tags path by the dot-notation string you provide.  
If you provide a `-prefix dev`, this would mean that `[[some.path]]` in your template becomes `[[dev.some.path]]` when referencing the credentials source JSON. 

if a path is prefixed inside the tag with `raw:`, whatever is in the JSON will be inserted as-is.  
If you have say an array of items, such as `[[raw:path.to.value]]`, then anything beyond that "value" would be inserted.

Using the -prefix, thus allows you to build make files and other pipelines that are "environment" aware in a simple way.  

Inside a json, an array, such as:

```json
{
  "dev": {
      "values": [
        "abc",
        "def",
        "ghi"
      ],
      "nameList": [
        {
          "name": "jane"
        },
        {
          "name": "joe"
        }
      ]
  },
  "prod": {
    "values": [
      "jlk",
      "mno",
      "pqr"
    ],
    "nameList": [
      {
        "name": "mike"
      },
      {
        "name": "perry"
      }
    ]
  }
}
```

Accessing the "def", would be values.1, as the indexes are 0-based, and the corresponding tag would be:
`[[dev.values.1]]`, likewise, `[[dev.nameList.1.name]]` would return "joe".

However, if you want to use a "generic" template, you could use the format:   
`[[values.1]]`, likewise, `[[nameList.1.name]]` 

The `-prefix dev` would return "joe" for `[[nameList.1.name]]`, while `-prefix prod` would return "perry".

## The "injson" / 1Password file

The format is a normal JSON file, and all values should be strings for simplicity.

Example of a Json credentials file.

```json
{
  "sql": {
	"host": "some.domain",
	"port": "3306",
	"user": "root",
	"pass": "someAwesomePassword"
  },
  "host": {
	"domain": "myCoolDomain.com",
	"port": "443",
	"certKey": "certificate.key",
	"cert": "certificate.pem",
	"certpass": "myKeyPassword"
  }
}
```

## 


### Example template for mapping credentials from 1PassWord. 

In the example below you can see how the tag starts with a double bracket and ends with a double bracket and inside has the path inside the json to the value in dot notation.
Thus, the 'sql.host' would be pointing tho the "sql" --> "host" object, and the entire tag '[[sql.host]]' would be replaced
with `some.domain`


sample-template.json
```json
{
	"item1": "[[sql.host]]",
	"item2": "[[sql.user]]",
	"item3": "[[sql.pass]]",
	"item4": "[[host.domain]]",
	"item5": "[[cred.UNKNOWN]]"
}
```

Using the following example: 
```plain text
1PassMapper -in sample-template.json -out config.json -vault CICD -item MySecretCollection
```
or, from a file: 
```plain text
1PassMapper -injson sampleJsonCreds.json -in sample-template.json -out config.json
```

would produce an output file "config.json" from the "sample-template.json", that would look like this:

config.json
```json
{
	"item1": "some.domain",
	"item2": "3306",
	"item3": "root",
	"item4": "myCoolDomain.com",
	"item5": "[[cred.UNKNOWN]]"
}
```
Noting that the path "cred.UNKNOWN" is not found in the source, and the tag will be left as-is. 

## Copyright information

[© EmberLabs® (BY-SA) (Attribution, Share-alike)](https://emberlabs.tech/copyright/)

- Similar to CC BY-SA
- This license enables reusers to distribute, remix, adapt, and build upon the material in any medium or format, so long as attribution is given to the creator.
- The license allows for commercial use.
- If you remix, adapt, or build upon the material, you must license the modified material under identical terms.
- A copy of the copyright license/terms must be retained as is in code or documents.
- EmberLabs (BY-SA) includes the following elements:
  - BY: Credit must be given to the creator.
  - SA: Adaptations must be shared under the same terms.



