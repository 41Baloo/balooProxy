# **Features**

## **TLS-Fingerprinting**

`TLS Fingerprinting` opens a whole new world of possibilities to defend against malicious attacks.

On one hand you can use `tls fingerprinting` to `whitelist` specific fingerprints, take for example seo bots, `blacklist` unwanted fingerprints, like for example wordpress exploit crawlers, ratelimit attackers that use proxies to change their ips or just simply gain more information about a visitor

## **Staged DDoS-Mitigation**

balooProxy comes with `3 distinct challenges`, in order to defend against bots/ddos attacks effectively, whilst effecting an actual users experience as little as possible. In order to archive that, balooProxy starts with the "weakest" and least notable challenge and automatically changes them when it detects one of them is being bypassed

### **Cookie Challenge**

The cookie challenge is completely invisible and supported by every webbrowser, aswell as most http libraries. It is an effective method to defend against simple ddos attacks

### **PoW JS Challenge**

The PoW JS challenge allows you to reliably block slightly more advanced bots while impacting the user experience as little as possible 

- Difficulty 5: ~3.100 Seconds
- Difficulty 4: ~0.247 Seconds
- Difficulty 3: ~0.244 Seconds
- Difficulty 2: ~0.215 Seconds
- Difficulty 1: ~0.212 Seconds

![Pow JS Challenge](https://cdn.discordapp.com/attachments/980872824577216532/1250383254171680830/image.png)

### **Custom Captcha**

The custom captcha should be your last resort or be used to protect especially weak webpages.

![Custom Captcha](https://cdn.discordapp.com/attachments/847520565606613042/1061764715577098250/image.png)

## **DDoS Alerts**

Always be informed when you are under attack of a (D)DoS attack with customisable discord alerts.

![Discord Attack Alerts](https://cdn.discordapp.com/attachments/1055573537148108941/1077581121832878140/image.png)

For more information on how to customise discord alerts refeer to 

## **Lightweight**

balooProxy tries to be as lightweight as possible, in order to run smoothly for everyone. Everything has its limits tho.

## **Cloudflare Mode**

Not everyone can afford expensive servers, aswell as a global cdn and this is fine. That's why balooProxy supports being used along with cloudflare, although this comes at the cost of a few features, like `tls fingerprinting`.

# **Installation**

## **Server Setup**

To start, download the [latest version of balooProxy](https://github.com/41Baloo/balooProxy/releases) balooProxy or compile it from source.

If you already have a `config.json` drag it in the same folder in your server as the `main` you downloaded/compiled. If you do not, simply start balooProxy by running `./main` and answer the questions the proxy asks you. After you answered those questions stop the proxy with `ctrl + c`.

# **Running**
You can run the proxy as a [service](https://abhinand05.medium.com/run-any-executable-as-systemd-service-in-linux-21298674f66f) or inside of a screen. To run the proxy inside a screen on ubuntu/debian first run `apt update`. After that is done install screen by running `apt install screen` and follow its installation process. To start running the proxy inside of a screen run `screen -S balooProxy`. This will put you inside a screen, making sure the proxy keeps running even when you log out of ssh. Now just start the proxy inside the screen by running `./main` (make sure the proxy isnt running anywhere else already) and quit the screen by pressing `ctrl + a + d`. You can always reopen the screen by running `screen -d -r`

# **Docker Setup**
To use balooProxy with Docker, start by executing the `./main` file to generate a config.json. Next, build the Docker image by running `docker build -t baloo-proxy .` in the same folder as the main file. Once the build is complete, run the Docker image using `docker run -d -p 80:80 -p 443:443 -t baloo-proxy`. To access the terminal of the Docker image, use `docker attach CONTAINERID`.
The container ID can be obtained by running `docker ps`. To detach from the terminal, press `Ctrl + p + q`. To stop the container, run `docker stop CONTAINERID`. To remove the container, use `docker rm CONTAINERID`, and to remove the image, run `docker rmi baloo-proxy`.

## **DNS Setup**

The proxy is now successfully running, however you still need to point your dns records to the proxy. To do so get the servers ip the proxy is currently running on. Go to your dns management and point the domain you want to proxy to the proxy ip via an `A` record, if the ip is an ipv4 or an `AAAA` record, if the ip is an ipv6. If you chose to use the proxy with Cloudflare, make sure the option "`Proxy status`" is set to "`Proxied`". If you chose not to use Cloudflare but are managing the dns via Cloudflare, make sure "`Proxy status`" is set to "`DNS only`". Also make sure no other records are pointing to your actual backend, since the proxy can otherwise be bypassed by attacking the backend directly, without first going through the proxy. After you did all of that wait ~10 minutes for the dns entry to register. You can check if your domain is successfully proxied by opening a new tab in the browser of your choice, opening dev tools, navigating to the network tab, opening your website, and searching for a "`baloo-proxy`" header in "Response Headers" of your request. If that exist, you successfully setup balooProxy

![DNS Example](https://cdn.discordapp.com/attachments/1007957829795201116/1094910870372483072/image.png)
![Network Tab](https://cdn.discordapp.com/attachments/1007957829795201116/1094912722174492672/image.png)


## **Configuration**
---

The `config.json` allows you to change several features and values about balooProxy. There are three main fields, `proxy`, `domains` and `rules`.

### **Proxy**
---

This field specifically allows you to change general settings about balooProxy

### `cloudflare` <sup>Bool</sup>

If this field is set to true balooProxy will be in cloudflare mode. 
(**NOTE**: `SSL/TLS encryption mode` in your cloudflare settings has to be set to "`Flexible`". Enabeling this mode without using cloudflare will also not work. Additionally, some features, such as `TLS-Fingerprinting` will not work and always return "`Cloudflare`")

### `maxLogLength` <sup>Int</sup>

This field sets the amount of logs entires shown in the ssh terminal

### `secret` <sup>Map[String]String</sup>

This field allows you to set the secret keys for the `cookie`, `js` and `captcha` challenge. It is highly advised to change the default values using [a tool](https://www.random.org/strings/?num=1&len=20&digits=on&upperalpha=on&loweralpha=on&unique=on&format=html&rnd=new) to generate secure secrets

### `ratelimits` <sup>Map[String]Int</sup>

This field allows you to set the different ratelimit values

**`requests`**: Amount of requests a single ip can send within 2 minutes

**`unknownFingerprint`**: Amount of requests a single unknown fingerprint can send within 2 minutes

**`challengeFailures`**: Amount of times a single ip can fail a challenge within 2 minutes

**`noRequestsSent`**: Amount of times a single ip can open a tcp connection without making http requests

### **Domains**
---

This field specifically allows you to change settings for a specific domain

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

### `webhook` <sup>Map[String]String</sup>

This field allows you to customise/enable discord DDoS alert notifications. It should be noted, discord alerts only get sent when the stage is **not** locked aswell as only when the first stage is bypassed and when the attack ended.

**`url`**: The webhook url the alert should be sent to. Refer to [Discords Introduction To Webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) for more information.

**`name`**: The name your alert should have displayed above it in discord

**`avatar`**: Url to the profile picture your alert should have inside discord

**`attack_start_msg`**: The message the alert should send when your domain is first under attack. Notice: you can use placeholders, like `{{domain.name}}`, `{{attack.start}}`, `{{attack.end}}`, `{{proxy.cpu}}` and `{{proxy.ram}}` here

**`attack_end_msg`**: The message the alert should send when your domain is no longer under attack. Notice: you can use placeholders, like `{{domain.name}}`, `{{attack.start}}`, `{{attack.end}}`, `{{proxy.cpu}}` and `{{proxy.ram}}` here

### **Firewall Rules**
---

Refer to [Custom Firewall Rules](#Custom-Firewall-Rules)

# **Terminal**

## **Main Hud**
---

The main hud shows you different information about your proxy

### `cpu`

Shows you the current cpu usage of the server balooProxy is running on in percent

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
---

The terminal allows you to input commands which change the behaviour of balooProxy

### `help`

The command `help` shows you a quick summary of all available commands. Type anything or press enter to exit it

### `stage`

The command `stage` followed by a number will set the proxies stage to said number
(**Note**: Setting the `stage` manually means the proxy will remain in that `stage` no matter what. Even if an attack is ongoing that bypasses this `stage`. Setting your `stage` to `0` will set the `stage` to 1 and enable automatic stage-switching again. Setting the `stage` to a number higher than `3` will result in all requests getting blocked)

### `domain`

The command `domain` followed by the name of a domain allows you to switch between your domains

### `add`

The command `add` prompts you with questions to add another domain to your proxy (**Note**: This can be done in the config.json aswell, however that currently requires your proxy to restart to apply the changes)

### `rtlogs`

The command `rtlogs` enables "real time logs", meaning the terminal log will not, like usually, update every second with the latest logs but will instead instantly update, as soon as there is another request to log. Notice, this might require a lot of cpu when your proxy is getting attacked


### `reload`

The command `reload` will cause the proxy to read the config.json again, aswell as reset some other generic settings, in order to apply changes from your config.json (**NOTE**: This is automatically executed every 5 hours)

# **Custom Firewall Rules**

Thanks to [gofilter]("https://github.com/kor44/gofilter") balooProxy allows you to add your own firewall rules by using a ruleset engine based on [wireguards display filter expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)

## **Fields**
---

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

### `http.headers` <sup>Map[String]String</sup>

Represents the headers send by the client (**Do not use!**. Not production ready)

### `proxy.stage` <sup>Int</sup>

Represents the stage the reverse proxy is currently in

### `proxy.cloudflare` <sup>Bool</sup>

Returns `true` if the proxy is in cloudflare mode

### `proxy.stage_locked` <sup>Bool</sup>

Returns `true` if the `stage` is locked to a specific stage

### `proxy.attack` <sup>Bool</sup>

Returns `true` if the proxy is under attack

### `proxy.bypass_attack` <sup>Bool</sup>

Returns `true` if the proxy is getting attacked by an attack that bypasses the current security measures

### `proxy.rps` <sup>Int</sup>

Represents the number of currently incoming requests per second

### `proxy.rps_allowed` <sup>Int</sup>

Represents the number of currently incoming requests per second forwarded to the backend

## **Comparison Operatos**
---

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
---

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
---


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
---

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
---
Rules are priorities from top to bottom in the `config.json`. A role has priority over every rule coming after it in the json.

(**Note**: As will later be described, some rules will stop balooProxy from checking for other matching rules. This is why it is recommended to have rules with higher `action` values be higher in the json aswell.)

## **Actions**
---

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

In this example, the rule checks whether or not the request is made by a socket and if so, challenges the request with a captcha.
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

# **API**

A full documentation of BalooProxies 2.0 API can be found at https://app.swaggerhub.com/apis-docs/BalooProxy/BalooProxy/2.0.0#/