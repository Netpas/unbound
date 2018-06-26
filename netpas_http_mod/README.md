### netpas_http_mod 模块
这是基于Unbound程序实现的一个模块,模块提供权威域的 TXT 域的查询，然后将查询内容进行后端进行查询，将查询到的IP地址的相关IPINFO信息，封装到TXT域中返回。

### 模块编译
```
./configure --prefix=xxx --enable-cachedb --with-libhiredis --with-pthreads --with-libevent
make
make install

```
### Unbound编译依赖库
* libevent-devel
* libhiredis(源码安装)
* expat-devel
* openssl-devel
* libcurl-devel(netpas_http_mod所依赖的库)
```
libcurl编译注意:dns 解析库用Linux自带的有问题，和Unbound冲突，应该使用c-ares异步解析库。
```

unbound 解析配置文件工具:
* byacc
* flex

### 模块配置参数
```
#Unbound需要关联的参数
	cache-max-ttl: 决定在redis的最大存活时间，（np-http-ttl必须小于它）
#后端关闭tcp转发，模块才生效
	tcp-upstream: no
#Unbound的主模块线程个数，每一个线程对应一个线程池
	num-threads: 3
#设置的模块执行顺序
	module-config: "cachedb validator netpas_http_mod iterator"
```

```
#线程池配置参数
netpas-pool:
	np-threads-pool-num: 100 #Unbound每一个线程对应的线程池大小
```

```
#后端http查询参数设置，可以根据权威域，配置多个(最多配置255个)
netpas-http:
	#http后端查询地址
	np-http-url: "http://127.0.0.1:80/hello"
	#http查询超时时间(单位:s,默认3s)
	np-http-timeout: 3
	#查询的权威(格式 xxx.xxx)
	np-auth-domain: "netpas.com"
	#对于每一个http查询的结果，在redis的存活时间(单位:s，默认604800，一个星期)
	np-http-ttl: 604800
```

### 使用例子
```
server:
	cache-max-ttl: 864000
	tcp-upstream: no
	num-threads: 3
	module-config: "cachedb validator netpas_http_mod iterator"
#数据库配置
cachedb:
	backend: "redis"
	redis-server-host: 127.0.0.1
	redis-server-port: 6379
#线程池配置
netpas-pool:
	np-threads-pool-num: 100
#http后端配置，可以多个
netpas-http:
	np-http-url: "http://127.0.0.1:80/hello"
	np-http-timeout: 3
	np-auth-domain: "netpas_1.com"
	np-http-ttl: 604800
netpas-http:
	np-http-url: "http://127.0.0.1:80/hello"
	np-http-timeout: 2
	np-auth-domain: "netpas_2.com"
	np-http-ttl: 60480

```

