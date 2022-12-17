# balooProxy
A lightweight http anti-ddos reverse-proxy made in golang

## Features

### Whitelabeling

The implemented challenges and specifically their design are ment to be code examples and placeholders so the end-user can modify then according to their liking

### API

balooProxy has several endpoints inbuild by default, such as `/_bProxy/fingerprint` to retrieve the visitors tls-fingerprint or `/_bProxy/stats` to get the proxys current statistics

### TLS-Fingerprinting

balooProxy can use a clients TLS-Fingerprint to automatically detect what browser/application a client uses, potentially black/whitelist them aswell as ratelimit unknown fingerprints to better mitigate DDoS Attacks that use a large proxy-pool

### Ratelimiting

- **IP Ratelimit**: Ratelimit how many times an ip can send requests in a minute
- **IP Challenge Ratelimit**: Ratelimit how many times an ip can request the verification challenge in a minute
- **TLS Ratelimit**: Ratelimit how many times a specific unknown fingerprint can send requests in a minute

### Stages

Automatically switches between different stages depending on currently ongoing DDoS attacks to block them effectively

**Stages**:

- **S1**: Nearly invisible cookie challenge
- **S2**: Invisible JS challenge
- **S3**: Captcha

Alternatively you can lock the proxy in one specific stage

## How to install

- store your ssl certificate with the name `server.crt` and your ssl key with the name `server.key`in the same directory as main.go
- start the script by running `./main [backend IP] [connection sceme to your backend ("http" or "https")]`
- enjoy :D
