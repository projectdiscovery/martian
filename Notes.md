## Dev Notes

### Broken Pipe / Connection Reset By Peer


**Context:**

when golang server closes a tcp connection it is assumed to be closen
however that isn't true because os considers/assumes the connection is still alive until it receive the final FIN-ACK packet.
and if os waits too long to gracefully close it golang internal scheduler considers this as active connection as reuses it
for subsequent request . which in turn causes `broken pipe`=>write on closed connection and `connection reset by peer`=> read of closed connection
to avoid such cases it is good idea to set linger to x sec (we use 3 sec) . Linger tells os to only wait for 3 sec for ^ FIN-ACK packet
Note: we can't make it zero for proxy use cases since the original behaviour of os connections ^ was introduced so that data is successfully commited
before it is sent . Since Both Client and Server in proxy are on same host 3 sec seems more than enough

```
Ref:
https://itnext.io/forcefully-close-tcp-connections-in-golang-e5f5b1b14ce6
https://gosamples.dev/broken-pipe/
```

>Note: ^ Errors are hidden by default and can be logged when `log.ShowHidden = true`

