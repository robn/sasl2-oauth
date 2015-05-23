# sasl2-oauth

An OAuth plugin for libsasl2

Right now implements the client part of the
[XOAUTH2](https://developers.google.com/gmail/xoauth2_protocol) mechanism. One
day it'd be nice to implement the OAUTHBEARER and OAUTH10A mechanisms from the
[KITTEN draft](https://tools.ietf.org/html/draft-ietf-kitten-sasl-oauth-22),
and maybe the original XOAUTH mechanism which is still seen in some places.

Use it just like the PLAIN and LOGIN mechanisms: pass the username as the
authzid and the bearer token as the password.

## install

```sh
./configure --prefix=/usr
make
sudo make install
```

## credits and license

Copyright © 1998-2003 Carnegie Mellon University

Copyright © 2015 Robert Norris

## contributing

Please hack on this and send pull requests :)
