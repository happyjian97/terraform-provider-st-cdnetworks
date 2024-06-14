---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "st-cdnetworks_http_header_config Resource - st-cdnetworks"
subcategory: ""
description: |-
  Http header configuration
---

# st-cdnetworks_http_header_config (Resource)

Http header configuration

## Example Usage

```terraform
resource "st-cdnetworks_http_header_config" "test" {
  domain_id = st-cdnetworks_shield_domain.test.domain_id
  
  header_rule {
    action = "add"
    header_direction = "cache2origin"
    header_name = "x-header-test"
    header_value = "test"
    path_pattern = "/*"
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `domain_id` (String) Domain ID

### Optional

- `header_rule` (Block List) Header rule (see [below for nested schema](#nestedblock--header_rule))

<a id="nestedblock--header_rule"></a>
### Nested Schema for `header_rule`

Optional:

- `action` (String) The control type of the http header supports the addition and deletion of the http header value. The optional value is add|set|delete, which is single-selected. Corresponding to the header-name and header-value parameters
                            Add: add a header
                            Set: modify the header
                            Delete: delete the header
                            Note: priority is delete>set>add
- `allow_regexp` (Boolean) Http header regular match, optional value: true / false.
                            True: indicates that the value of the header-name is handled as a regular match.
                            False: indicates that the value of the header-name is processed according to the actual parameters, and no regular match is made.
                            Do not pass the default is false
- `custom_file_type` (String) Matching condition: Custom file type, separate by semicolon.
- `custom_pattern` (String) Matching conditions: specify common types, optional values are all or homepage. 1. all: all files 2. homepage: home page
- `directory` (String) directory
- `except_path_pattern` (String) Exception url matching pattern, support regular. Example:
- `file_type` (String) Matching conditions: file type, please separate by semicolon, optional values: gif png bmp jpeg jpg html htm shtml mp3 wma flv mp4 wmv zip exe rar css txt ico js swf m3u8 xml f4m bootstarp ts.
- `header_direction` (String) The control direction of the http header, the optional value is cache2visitor/cache2origin/visitor2cache/origin2cache, single-select.
                            Cache2origin refers to the source direction---corresponding to the configuration item return source request;
                            Cache2visitor refers to the direction of the client back - the corresponding configuration item returns to the client response;
                            Visitor2cache refers to receiving client requests
                            Origin2cache refers to the receiving source response
- `header_name` (String) Http header name, add or modify the http header, only one is allowed; delete the http header to allow multiple entries, separated by a semicolon ';'.
                            Note: The operation of the special http header is limited, and the http header and operation type of the operation are allowed.
                            This item is required and cannot be empty
                            When the action is add: indicates that the header-name header is added.
                            When the action is set: modify the header-name header
                            When the action is delete: delete the header-name header
- `header_value` (String) The value corresponding to the HTTP header field, for example: mytest.example.com

            Note:

            1. When the action is add or set, the input parameter must be passed a value

            2. When the action is delete, the input parameter is not passed

            Support to get the value of specified variable by keyword, such as client IP, including:

            Key words: meaning

#timestamp: current time, timestamp as 1559124945
#request-host: host in the request header
#request-url: request url, which contains the full path of the protocol domain name, etc., such as http://aaa.aa.com/a.html
#request-uri: request uri, relative path format, such as /index.html
#origin- IP: return source IP
#cache-ip: edge node IP
#server-ip: external service IP
#client-ip: client IP, or visitor IP
#response-header{XXX} : get the value in the response header, such as #response-header{etag}, get the etag value in response-header

#header{XXX} : to get the value in the HTTP header of the request, such as #header{user-agent}, is to get the user-agent value in the header

#cookie{XXX} : get the value in the cookie, such as #cookie{account}, is to get the value of the account set in the cookie
- `path_pattern` (String) The url matching mode supports fuzzy regularization. If all matches, the input parameters can be configured as: *
- `request_header` (String) Match request header, header values support regular, header and header values separated by Spaces, e.g. : Range bytes=[0-9]{9,}
- `request_method` (String) The matching request method, the optional values are: GET, POST, PUT, HEAD, DELETE, OPTIONS, separate by semicolons.
- `specify_url_pattern` (String) Matching Condition: Specify URL. The input parameter does not support the URI format starting with http(s)://