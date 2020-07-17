+++
author = "Preston Kemp"
title = "Security Engineering and the Pandemic"
date = "2019-11-20"
description = "Some quick thoughts on the use of TLS inspection devices in enterprise networks"
tags = ["infosec"]
image = "https://static.prestonkemp.com/photos/forest-simon-WbhLL-nivYM-unsplash.jpg"
+++

<!--more-->

Something I've noticed in my professional life is the propensity on the part of technical people to try and solve imaginary problems.

I think that TLS inspection is one of those imaginary problems.

If you ask people what they hope to accomplish using TLS inspection they'll say things like:

1. Protecting Intellectual Property (DLP)
2. Protecting other Organizational Secrets (DLP)
3. Stopping malicious requests

These are valid goals, but it's unclear how TLS inspection accomplishes any of them.

Some broad questions about the efficacy of this approach that immediately come to mind are:

1. How does this not turn into something that just has hundreds (if not thousands) of false positives every single day? Is someone going to review them? Do you really have the manpower to do this sort of thing? And even if you did, unless a flagged request was blocked how much good is knowing about it after the fact?
2. What are the privacy and security implications of doing this? Do your users know you're doing it? Do they understand you have access to their plaintext credit card numbers, passwords, security questions, etc?
3. If one of your goals is to stop malformed or otherwise malicious requests, wouldn't your time be better spent patching vulnerable systems rather than putting another system that also needs to be patched in front of said vulnerable system?
4. TLS inspection only works on networks that you can control. How will you stop data exfiltration from users that work remotely?

Some more specific areas of concern:

## 1. TLSi Violates the Principle of Least Privilege

The white paper (if you can call it that) I reference above makes note that Insider Threats could result in compromise of user data, and could itself become a target of attack.

The white paper goes on to state that enterprises that choose to implement this technology should ensure that they are following the principle of "least privilege"

The problem with this suggestion is that it is neither useful nor honest. How can an organization ever hope to implement the principle of least privilege while purposefully injecting massive amounts of it in an unnecessary way? How can you prevent user data from being compromised in transit while breaking the thing that is meant to provide that protection (TLS).

***

## 2. TLSi complicates your attack surface

As an exercise for the security-conscious, consider the following:

1. What happens to data after its *only* protection is broken?
  1. Is it routed in plain-text through racks of equipment for further inspection? Who has access to those racks? What prevents someone from altering a route inside this construct to siphon off interesting data?
  2. What do those inspection devices do with user data?
2. Do you know what SSL/TLS library your TLSi device uses? Is it open-source? Reputable? Up-to-date?

## 3. What are you *even* doing with it?

As discussed previously, TLS inspection has a valid set of goals, but there's never a conversation about the efficacy of this approach. Did deep packet inspection work well even when the majority of traffic was sent in the clear? If not, perhaps a different approach would more meaningfully address these concerns.

## 4. TLSi only works on networks that you control

Why can't a user just download whatever data they need, go to Starbucks and upload it?

## 5. Privacy Implications

Someone will argue that users don't have an reasonable expectation of privacy on a corporate network, but that's a bad faith argument. It's incredibly deceptive (maybe even *evil*) to pretend that users should understand that to mean that their employer could have access to any personal information they enter on a website.

Do your users understand the security and privacy implications of what you're doing?

Do your users understand that you have access to their plain-text passwords, credit card numbers, security questions, etc? (a simple regex could be used to steal credit card numbers, social security numbers, etc.)

Even if your users have no "reasonable expectation of privacy" on your network, are your users aware of the implications of what you're doing so they can make an informed decision (informed consent)?

How would you feel if someone was in a position to steal all of your personal information, read your emails, etc?

Someone who operates one of these devices (or is capable of performing a plain-text capture) of data has a tremendous amount of power, how can you be confident that would result in user data abuse?

## 6. Poor User Experience

When behind an inspection device connection failures are almost never communicated to the end user. The connection is simply reset by the inspection device and the user is left wondering why.

## 7. All Software has bugs

Security software is not immune to bugs simply by virtue of being security software. All security software has bugs.

This has been written about extensively, so I won't belabor the point here, but security software very often injects privleges into software as a means to achieve its objective. things in order to achieve some security objective. In the In software such as anti-virus, this is achieved by process injection or by other methods of privilege injection.

Do you know what cryptographic library your TLS inspection device uses? When was it last updated?

Below is a bug from iOS 7 (famously referred to as #gotofail), the bug in question was part of the SSL library for iOS devices. The bug (line 12) illustrates the point that even well written security software has bugs.

### sslKeyExchange.c

```C

if ((err = SSLFreeBuffer(&hashCtx)) != 0)
        goto fail;

    if ((err = ReadyHash(&SSLHashSHA1, &hashCtx)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &clientRandom)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &serverRandom)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0)
        goto fail;
        goto fail;
    if ((err = SSLHashSHA1.final(&hashCtx, &hashOut)) != 0)
        goto fail;

	err = sslRawVerify(ctx,
                       ctx->peerPubKey,
                       dataToSign,				/* plaintext */
                       dataToSignLen,			/* plaintext length */
                       signature,
                       signatureLen);
	if(err) {
		sslErrorLog("SSLDecodeSignedServerKeyExchange: sslRawVerify "
                    "returned %d\n", (int)err);
		goto fail;
	}

fail:
    SSLFreeBuffer(&signedHashes);
    SSLFreeBuffer(&hashCtx);
    return err;

}

```

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Hello, world!</title>
  </head>
  <body>
    <h1>Hello, world!</h1>
  </body>
</html>
```
