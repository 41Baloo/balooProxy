# **Features**

## **Performance**

balooProxy is designed to be as minimalistic as possible. It can be run effectively on extremely cheap servers (which is not to say it has infinite performance. Worse servers will have less performance).

If you find anything that can be improved in the source code, feel free to let me know and/or open a pull request/issue.

## **DDoS Protection**

### **stages**
---

balooProxy has `3` different stages in order to automatically mitigate `DDoS` attacks. When your website is under attack and the stage is not locked to a specific stage, balooProxy will automatically engage the next stage once your configured threshold has been hit and disengage it once it deems the attack to be over.

### `1` <sup>Cookie Challenge</sup>

This `stage` is the default stage and always on. It will challenge visitors with an invisible cookie challenge which is invisible to browsers and can be passed by most good bots. If you want to whitelist specific requests from this challenge use domain specific `custom firewall rules` for that.

### `2` <sup>JS Challenge</sup>

This `stage` will be engaged if you manually set it or `stage 1` gets bypassed. It will present every visitor with an invisible javascript challenge. Browsers will not be able to see it, however automated requests, good or bad, will most likely not pass it autmatically. Use domain specific `custom firewall rules` in order to whitelist good bots from this challenge.

### `3` <sup>Captcha</sup>

This `stage` will be engaged when both `stage 1` and `stage 2` have been bypassed. It will present every visitor with a text based captcha. This will stop almost every attack but can also be annoying to users. Use domain specific `custom firewall rules` in order to whitelist requests.

![Captcha Image](https://cdn.discordapp.com/attachments/847520565606613042/1061764715577098250/image.png)

### **custom firewall rules**

balooProxy gives you the ability to configure your own `firewall rules` in the `config.json` in order to make balooProxy even more effective at blocking unwanted requests specifically for your website(s) and/or whitelist certain requests. For more information refer to [Custom Firewall Rules](#**Custom-Firewall-Rules**).

### **tls fingerprints**
---

balooProxy automatically fingerprints every request passively using `tls fingerprints`. This allows you to block or whitelist certain `tls fingerprints` to make your `custom firewal rules` even harder to bypass and only allow good and wanted visitors/bots.

### **global ratelimit**
---

balooProxy can globaly ratelimit spamming `IPs`, aswell as `tls fingerprints`. BalooProxy gives you the option to block spamming `IPs` or `IPs` that failed challenges multiple times for 2 minutes. It also gives you the ability to ratelimit `unknown tls fingerprints`. All of these thresholds can be configured in the `config.json` (**Note**: These ratelimits are global. If your proxy proxies multiple domains, a ratelimited `IP`/`Fingerprint` will be banned for 2 minutes on all of them).

### **attack alerts**
---

balooProxy can automatically send alerts to a `discord webhook` whenever your website is getting attacked by a bypassing attack aswell as more detailed alerts after your website is no longer getting attacked that include a `graph` showing total and allowed requests over time.

![Discord Webhook Alert](https://cdn.discordapp.com/attachments/847520565606613042/1061765358882668583/image.png)

### **cloudflare compatible**
---

You can use balooProxy behind cloudflare in order to hide your IPv4 address (**Note**: Some features might not work in cloudflare mode. Refer to [Installation](#**Installation**)).

## **Configurable**

You can change almost every setting about balooProxy in your `config.json`.

# **Installation**

In order to install balooProxy you need the `config.json` aswell as the compiled version of balooProxy.

## **Configuration**

The `config.json` allows you to change several features and values about balooProxy. There are three main fields, `proxy`, `domains` and `rules`. Example configurations can be found in the `config.json`.

### **Proxy**
---

This field specifically allows you to change general settings about balooProxy.

### `cloudflare` <sup>Bool</sup>

If this field is set to true balooProxy will be in cloudflare mode. 
(**NOTE**: `SSL/TLS encryption mode` in your cloudflare settings has to be set to "`Flexible`". Enabeling this mode without using cloudflare will also not work. Additionally, some features, such as `TLS-Fingerprinting` will not work and always return "`Cloudflare`").

### `maxLogLength` <sup>Int</sup>

This field sets the amount of logs entires shown in the ssh terminal.

### `secrets`

This field allows you to set the secret keys for the `cookie`, `js` and `captcha` challenge. It is highly advised to change the default values using [a tool](https://www.random.org/strings/?num=1&len=20&digits=on&upperalpha=on&loweralpha=on&unique=on&format=html&rnd=new) to generate secure secrets.

### `ratelimits`

This field allows you to set the different ratelimit values. (**Note**: These ratelimits are global and not ment to be used for individual sites. These ratelimits are supposed to protect your proxy from wasting cpu on spamming requests).

**`requests`**: Amount of requests a single ip can send within 2 minutes.

**`unknownFingerprint`**: Amount of requests a single unknown fingerprint can send within 2 minutes.

**`challengeFailures`**: Amount of times a single ip can fail a challenge within 2 minutes.

**`noRequestsSent`**: Amount of times a single ip can open a tcp connection without making http requests.

### **Domains**
---

This field specifically allows you to change settings for a specific domain.

### `name` <sup>String</sup>

The domains name (For example `example.com`)

### `scheme` <sup>String</sup>

The scheme balooProxy should use to communicate with your backend (Can be `http` or `https`. Generally you should use `http` as it is faster and less cpu intensive)

### `backend` <sup>String</sup>

Your backends ip (**Note**: You can specify ports by using the following format `1.1.1.1:8888`)

### `certificate` <sup>String</sup>

Path to your ssl certificate (For example `server.crt` or `/certificates/example.com.crt`)

### `key` <sup>String</sup>

Path to your ssl private key (For example `server.key` or `/keys/example.com.key`)

### `webhook`

This field allows you to modify your alert webhooks. Every time a domain is attacked by an attack that bypasses at least `stage 1`, balooProxy will send a `discord` webhook alert. Once when your domain comes under attack and a more detailed alert with a graph after the attack is over.

**`url`**: The url the alert will be sent to (Leave empty if you don't want webhook alerts)

**`name`**: Webhook name

**`avatar`**: Url to webhook profile picture

**`attack_start_msg`**: Message that should be displayed when the website is getting attacked (**Note**: `{{domain.name}}` will get replaced with your domain name. For example "The website {{domain.name}} is under attack" will display as "The website example.com is under attack").

**`attack_stop_msg`**: Message that should be displayed when the website is no longer getting attacked (**Note**: `{{domain.name}}` will be replaced with your domain name here aswell)

### `rules`

Allows you to configure custom firewall rules for every domain. For more information refer to [Custom Firewall Rules](#**Custom-Firewall-Rules**)

### `bypassStage1`

Allows you to configure the threshold of `allowed` requests per second at which balooProxy should consider `stage 1` to be bypassed and `switch` to `stage 2` (JS Challenge)

### `bypassStage2`

Allows you to configure the threshold of `allowed` requests per second at which balooProxy should consider `stage 2` to be bypassed and `switch` to `stage 3` (Captcha)

### `disableBypassStage3`

If the number of `allowed` requests per second is lower than this one **and** if `disableRawStage3` is also true, balooProxy disables `stage 3` and engages `stage 2`

### `disableRawStage3`

If the number of `total` requests per second is lower than this one **and** if `disableBypassStage3` is also true, balooProxy disables `stage 3` and engages `stage 2`

### `disableBypassStage2`

If the number of `allowed` requests per second is lower than this one **and** if `disableRawStage2` is also true, balooProxy disables `stage 2` and engages `stage 1`

### `disableRawStage2`

If the number of `total` requests per second is lower than this one **and** if `disableBypassStage2` is also true, balooProxy disables `stage 2` and engages `stage 1`

# **Custom Firewall Rules**

Thanks to [gofilter]("https://github.com/kor44/gofilter") balooProxy allows you to add your own firewall rules by using a ruleset engine based on [wireguards display filter expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html).

## **Fields**

### `ip.src` <sup>IP</sup>

Represents the clients ip address

### `ip.engine` <sup>String</sup>

Represents the clients browser ("") if not applicable

### `ip.bot` <sup>String</sup>

Represents the bots name ("") if not applicable

### `ip.fingerprint` <sup>String</sup>

Represents the clients raw tls fingerprint

### `ip.http_requests` <sup>Int</sup>

Represents the clients total forwarded http requests in the last 2 minutes

### `ip.challenge_requests` <sup>Int</sup>

Represents the clients total attempts at solving a challenge in the last 2 minutes

### `http.host` <sup>String</sup>

Represents the hostname of the current domain

### `http.version` <sup>String</sup>

Represents the http version used by the client (either `HTTP/1.1` or `HTTP/2`)

### `http.method` <sup>String</sup>

Represents the http method used by the client (all capital)

### `http.query` <sup>String</sup>

Represents the raw query string sent by the client

### `http.path` <sup>String</sup>

Represents the path requested by the client (e.g. `/pictures/dogs`)

### `http.user_agent` <sup>String</sup>

Represents the user-agent sent by the client (**Important**: will always be lowercase)

### `http.cookie` <sup>String</sup>

Represents the cookie string sent by the client

### `http.headers` <sup>String</sup>

Represents the headers send by the client in Map format as a string

### `proxy.stage` <sup>Int</sup>

Represents the stage the reverse proxy is currently in

### `proxy.cloudflare` <sup>Bool</sup>

Returns `true` if the proxy is in cloudflare mode

### `proxy.stage_locked` <sup>Bool</sup>

Returns `true` if the `stage` is locked to a specific stage

### `proxy.bypass_attack` <sup>Bool</sup>

Returns `true` if the proxy is getting attacked by an attack that bypasses the current security measures

### `proxy.rps` <sup>Int</sup>

Represents the number of currently incoming requests per second

### `proxy.rps_allowed` <sup>Int</sup>

Represents the number of currently incoming requests per second forwarded to the backend

## **Comparison Operatos**

Check if two values are identical

`eq`, `==`
```
(http.path eq "/")

(http.path == "/")
```


Check if two values are not identical

`ne`, `!=`
```
(http.path ne "/")

(http.path != "/")
```


Check if the value to the left is bigger than the value to the right

`gt`, `>`
```
(proxy.rps gt 200)

(proxy.rps > 200)
```


Check if the value to the right is bigger than the value to the left

`lt`, `<`
```
(proxy.rps lt 10)

(proxy.rps < 10)
```


Check if value to the left is bigger or equal to the value to the right

`ge`, `>=`
```
(proxy.rps_bypassed ge 50)

(proxy.rps_bypassed >= 50)
```


Check if value to the right is bigger or equal to the value to the left

`le`, `<=`
```
(proxy.rps_bypassed le 50)

(proxy.rps_bypassed <= 50)
```

## **Logical Operators**

Require both comparisons to return true

`and`, `&&`
```
(http.path eq "/" and http.query eq "")

(http.path eq "/" && http.query eq "")
```


Require either one of the comparisons to return true

`or`, `||`
```
(http.path eq "/" or http.query eq "/alternative")

(http.path eq "/" || http.query eq "/alternative")
```


Require comparison to return false to be true

`not`, `!`
```
!(http.path eq "/" and http.query eq "")

not(http.path eq "/" && http.query eq "")
```

## **Search / Match Operators**


Returns true if field contains value

`contains`
```
(http.user_agent contains "chrome")
```


Returns true if field matches a regex expression

`matches`
```
(http.header matches "(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)")
```

## **Structure**

Firewall rules are build in the `config.json` and have the following structure

```
"rules": [
        {
            "expression": "(http.path eq \"/captcha\")",
            "action": "3"
        },
        {
            "expression": "(http.path eq \"/curl\" and ip.bot eq \"Curl\")",
            "action": "0"
        }
    ]
```

Every individual has to have the `expression` and `action` field.

## **Priority**

Rules are priorities from top to bottom in the `config.json`. A role has priority over every rule coming after it in the json.

(**Note**: As will later be described, some rules will stop balooProxy from checking for other matching rules. This is why it is recommended to have rules with higher `action` values be higher in the json aswell.)

## **Actions**


The resulting action to a rule is decided based on the `"susLv"`, which is a scale from `0`-`3` how suspicious/malicious the request is. The `susLv` itself starts of at the current `stage` balooProxy is in. This is normally `1` but might change to `2` and `3` depending on how many bypassing requests balooProxy currently experiences.

Each number has its own reaction.

### `0` <sup>Allow</sup>

The request is whitelisted and will not be challenged in any form

### `1` <sup>Cookie Challenge</sup>

The request will be challenged with a simple cookie challenge which will be passed automatically by most good bots

### `2` <sup>JS Challenge</sup>

The request will be challenged with a javascript challenge which will stop most bots, including good once

### `3` <sup>Captcha</sup>

The request will be challenged with a visual captcha. The user will have to input text he sees on a picture. Will stop most malicious requests aswell as good bots

### `4 or higher` <sup>Block</sup>

Every request with a susLv of 4 or higher will be blocked

## **Adding Actions**
---
You can set a rules action to be a specific action by setting it's `action` to a specific number 

(**Note**: If a rule matches a request and sets the `action` to a specific number balooProxy will not check for other matching rules. Hence you should usually give rules with a higher `action` value a lower `priority` value aswell).

```
{
    "expression": "(http.host contains \":\")",
    "action": "3"
}
```

In this example, the rule checks whether or not the request is made by a socket and if so, challenges the request with a captcha. (**Note**: With balooProxy 1.0 the current domain management system doesnt allow port specifications if they have not been specified in the `config.json`, making this rule useless at the moment)
***

You can also set actions more dynamically by using a `+` in front of the `action` value. This will tell balooProxy that you want to increase the *current* susLv of the request by the amount specified after the `+`.

(**Note**: actions that use a `+` do not stop balooProxy from checking if further rules match, if the rule matches. This allows you to stack multiple checks ontop of each other and set reactions more dynamically and react less aggressively when not attacked)

```
{
    "expression": "(http.engine eq \"\")",
    "action": "+1"
}
```

In this example, the rule checks whether or not the request is made by a known browser. If not, the `susLv` gets raised by `1`.
***

Similar to using `+` can also set a `-` in front of the `action` value. This will tell balooProxy that you want to decrease the *current* susLv of the request by the amount specified after the `-`.

```
{
    "expression": "(proxy.stage eq 3 and http.useragent contains \"windows\")",
    "action": "-1"
}
```

In this example, the rule checks whether or not the request is made by a Windows useragent when the `stage` is `3` and decreases the `susLv` by one, making it not show a captcha for Windows users but also not skipping rules that might come after this rule

## **Examples**

```
{
    "expression": "(proxy.stage eq 1)",
    "action": "-1"
}
```

This rule will disable stage 1 for every request but still keep the auto mitigation active, aswell as allow other rules that might follow after it or were in front of it, to still be considered

```
{
    "expression": "((ip.engine eq \"Firefox\" and http.user_agent contains \"chrome\") or (ip.engine eq \"Chromium\" and http.user_agent contains \"firefox\"))",
    "action": "3"
}
```

This rule checks if the useragent missmatches the `browser engine` associated with the `tls fingerprint`. If so, the request gets presented with a captcha.

```
{
    "expression": "(http.path eq \"/curl\" and ip.bot eq \"Curl\")",
    "action": "0"
},
{
    "expression": "(http.path eq \"/curl\")",
    "action": "4"
}
```

This rule-chain only allows `Curl` to make requests to the path `/curl`

# **Terminal**

## **Main Hud**


The main hud shows you different information about your proxy

### `cpu`

Shows you the current cpu usage of the server balooProxy is running on in percent

### `domain`

Shows you the domain name you are currently inspecting

### `stage`

Shows you the stage balooProxy is currently in

### `stage locked`

Shows `true` if the stage was manually set and locked by using the `stage` command in the terminal

### `total`

Shows the number of all incoming requests per second to balooProxy

### `bypassed`

Shows the number of requests per second that passed balooProxy and have been forwarded to the backend

### `connections`

Shows the current amount of open L4 connections to balooProxy

### `latest logs`

Shows information about the last requests that passed balooProxy (The amount can be specified in `config.json`)

## **Commands**

The terminal allows you to input commands which change the behaviour of balooProxy

### `stage`

The command `stage` followed by a number will set the proxies stage to said number
(**Note**: Setting the `stage` manually means the proxy will remain in that `stage` no matter what. Even if an attack is ongoing that bypasses this `stage`. Setting your `stage` to `0` will set the `stage` to 1 and enable automatic stage-switching again. Setting the `stage` to a number higher than `3` will result in all requests getting blocked)

### `domain`

The command `domain` followed by a domain name will make the proxy display the statistics of said domain. Other changes, such as the `stage` command will also now apply to this domain. Only typing "`domain`" followed by nothing else will list the available domains currently loaded in balooProxy. By default the proxy starts on the first domain in your `config.json`