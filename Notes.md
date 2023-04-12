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


### Malformed Chunked Encoding

According to RFC other widely known implementations of http proxy. `Transfer-Encoding` is considered as Hop-by-Hop header which means it is totally upto proxy implementation how to implement it. `httputil.ReverseProxy` simply strips `Transfer-Encoding` and sends a normal CL based response. If http proxy decides to implement transfer-encoding there are two choices read and buffer x chunks from server and stream response to client **or** read all resp.Body in buffer/memory and then write/stream. 

we at @projectdiscovery will be sticking with reading all response body at once and keeping `Transfer-Encoding`. since dsl variables need body to evalutate expressions and it is accepted that we load resp body in memory in `proxify` . http std lib internally handles `chunked body` so no need to handle it explicitly, while writing to conn using `res.Write` std lib peeks body content and writes body in appropriate format (i.e chunked). adding/using `httputil.NewChunkedWriter` causes nested/malformed chunks.

Currently martian internally converts transfer-encoding to non-chunked (i.e CL format) as soon as it receives http.Response after all Modifiers are executed at the time of writing to connection it is converted back to Transfer-Encoding. this avoids all errors caused by reading chunked body twice (cause for malformed encoding)

```
Ref:
https://github.com/golang/go/blob/master/src/net/http/httputil/reverseproxy.go
https://stackoverflow.com/questions/29486086/how-http2-http1-1-proxy-handle-the-transfer-encoding
https://github.com/chimurai/http-proxy-middleware/issues/324
```