/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */
"use strict";"require form";"require network";"require uci";"require v2ray";return L.view.extend({load:function(){return Promise.all([v2ray.getLocalIPs(),v2ray.getCore()])},render:function(e){var o,s=void 0===e?[]:e,t=s[0],a=void 0===t?[]:t,r=s[1],l=void 0===r?"":r,n=new form.Map("v2ray","%s - %s".format(l,_("Inbound"))),d=n.section(form.GridSection,"inbound");d.addremove=!0,d.sortable=!0,d.sectiontitle=function(e){return uci.get("v2ray",e,"alias")},d.modaltitle=function(e){var o=uci.get("v2ray",e,"alias");return _("Inbound")+" > "+(null!=o?o:_("Add"))},d.nodescriptions=!0,d.tab("general",_("General Settings")),d.tab("stream",_("Stream Settings")),d.tab("other",_("Other Settings")),(o=d.taboption("general",form.Value,"alias",_("Alias"))).modalonly=!0,o.rmempty=!1,(o=d.taboption("general",form.Value,"listen",_("Listen"))).datatype="ipaddr";for(var m=0,p=a;m<p.length;m++){var i=p[m];o.value(i)}(o=d.taboption("general",form.Value,"port",_("Port"))).rmempty=!1,o.datatype="or(port, portrange)",(o=d.taboption("general",form.ListValue,"protocol",_("Protocol"))).value("dokodemo-door","Dokodemo-door"),o.value("http","HTTP"),o.value("mtproto","MTProto"),o.value("shadowsocks","Shadowsocks"),o.value("socks","Socks"),o.value("vmess","VMess"),(o=d.taboption("general",form.Value,"s_dokodemo_door_address","%s - %s".format("Dokodemo-door",_("Address")),_("Address of the destination server."))).modalonly=!0,o.depends("protocol","dokodemo-door"),o.datatype="host",(o=d.taboption("general",form.Value,"s_dokodemo_door_port","%s - %s".format("Dokodemo-door",_("Port")),_("Port of the destination server."))).modalonly=!0,o.depends("protocol","dokodemo-door"),o.datatype="port",(o=d.taboption("general",form.MultiValue,"s_dokodemo_door_network","%s - %s".format("Dokodemo-door",_("Network")),_("If transparent proxy enabled on current inbound, this option will be ignored."))).modalonly=!0,o.depends("protocol","dokodemo-door"),o.value("tcp"),o.value("udp"),o.default="tcp",(o=d.taboption("general",form.Value,"s_dokodemo_door_timeout","%s - %s".format("Dokodemo-door",_("Timeout")),_("Time limit for inbound data(seconds)"))).modalonly=!0,o.depends("protocol","dokodemo-door"),o.datatype="uinteger",o.placeholder="300",(o=d.taboption("general",form.Flag,"s_dokodemo_door_follow_redirect","%s - %s".format("Dokodemo-door",_("Follow redirect")),_("If transparent proxy enabled on current inbound, this option will be ignored."))).modalonly=!0,o.depends("protocol","dokodemo-door"),(o=d.taboption("general",form.Value,"s_dokodemo_door_user_level","%s - %s".format("Dokodemo-door",_("User level")),_("All connections share this level"))).modalonly=!0,o.depends("protocol","dokodemo-door"),o.datatype="uinteger",(o=d.taboption("general",form.Value,"s_http_account_user","%s - %s".format("HTTP",_("Account user")))).modalonly=!0,o.depends("protocol","http"),(o=d.taboption("general",form.Value,"s_http_account_pass","%s - %s".format("HTTP",_("Account password")))).modalonly=!0,o.depends("protocol","http"),o.password=!0,(o=d.taboption("general",form.Flag,"s_http_allow_transparent","%s - %s".format("HTTP",_("Allow transparent")))).modalonly=!0,o.depends("protocol","http"),(o=d.taboption("general",form.Value,"s_http_timeout","%s - %s".format("HTTP",_("Timeout")),_("Time limit for inbound data(seconds)"))).modalonly=!0,o.depends("protocol","http"),o.datatype="uinteger",o.placeholder="300",(o=d.taboption("general",form.Value,"s_http_user_level","%s - %s".format("HTTP",_("User level")),_("All connections share this level"))).modalonly=!0,o.depends("protocol","http"),o.datatype="uinteger",(o=d.taboption("general",form.Value,"s_mtproto_user_email","%s - %s".format("MTProto",_("User email")))).modalonly=!0,o.depends("protocol","mtproto"),(o=d.taboption("general",form.Value,"s_mtproto_user_secret","%s - %s".format("MTProto",_("User secret")))).modalonly=!0,o.depends("protocol","mtproto"),o.password=!0,(o=d.taboption("general",form.Value,"s_mtproto_user_level","%s - %s".format("MTProto",_("User level")),_("All connections share this level"))).modalonly=!0,o.depends("protocol","mtproto"),o.datatype="uinteger",(o=d.taboption("general",form.Value,"s_shadowsocks_email","%s - %s".format("Shadowsocks",_("Email")))).modalonly=!0,o.depends("protocol","shadowsocks"),(o=d.taboption("general",form.ListValue,"s_shadowsocks_method","%s - %s".format("Shadowsocks",_("Method")))).modalonly=!0,o.depends("protocol","shadowsocks"),o.value(""),o.value("aes-256-cfb"),o.value("aes-128-cfb"),o.value("chacha20"),o.value("chacha20-ietf"),o.value("aes-256-gcm"),o.value("aes-128-gcm"),o.value("chacha20-poly1305"),o.value("chacha20-ietf-poly1305"),(o=d.taboption("general",form.Value,"s_shadowsocks_password","%s - %s".format("Shadowsocks",_("Password")))).modalonly=!0,o.depends("protocol","shadowsocks"),o.password=!0,(o=d.taboption("general",form.Value,"s_shadowsocks_level","%s - %s".format("Shadowsocks",_("User level")))).modalonly=!0,o.depends("protocol","shadowsocks"),o.datatype="uinteger",(o=d.taboption("general",form.Flag,"s_shadowsocks_ota","%s - %s".format("Shadowsocks",_("One Time Auth (OTA)")))).modalonly=!0,o.depends("protocol","shadowsocks"),(o=d.taboption("general",form.MultiValue,"s_shadowsocks_network","%s - %s".format("Shadowsocks",_("Network")))).modalonly=!0,o.depends("protocol","shadowsocks"),o.value("tcp"),o.value("udp"),o.default="tcp",(o=d.taboption("general",form.ListValue,"s_socks_auth","%s - %s".format("Socks",_("Auth")))).modalonly=!0,o.depends("protocol","socks"),o.value(""),o.value("noauth",_("No Auth")),o.value("password",_("Password")),o.default="noauth",(o=d.taboption("general",form.Value,"s_socks_account_user","%s - %s".format("Socks",_("Account user")))).modalonly=!0,o.depends("s_socks_auth","password"),(o=d.taboption("general",form.Value,"s_socks_account_pass","%s - %s".format("Socks",_("Account password")))).modalonly=!0,o.depends("s_socks_auth","password"),o.password=!0,(o=d.taboption("general",form.Flag,"s_socks_udp","%s - %s".format("Socks",_("UDP")))).modalonly=!0,o.depends("protocol","socks"),(o=d.taboption("general",form.Value,"s_socks_ip","%s - %s".format("Socks",_("IP")),_("IP address of current host"))).modalonly=!0,o.depends("s_socks_udp","1");for(var u=0,c=a;u<c.length;u++){i=c[u];o.value(i)}return o.datatype="host",o.placeholder="127.0.0.1",(o=d.taboption("general",form.Value,"s_socks_user_level","%s - %s".format("Socks",_("User level")),_("All connections share this level"))).modalonly=!0,o.depends("protocol","socks"),o.datatype="uinteger",(o=d.taboption("general",form.Value,"s_vmess_client_id","%s - %s".format("VMess",_("Client ID")))).modalonly=!0,o.depends("protocol","vmess"),(o=d.taboption("general",form.Value,"s_vmess_client_alter_id","%s - %s".format("VMess",_("Client alter ID")))).modalonly=!0,o.depends("protocol","vmess"),o.datatype="and(min(0), max(65535))",(o=d.taboption("general",form.Value,"s_vmess_client_email","%s - %s".format("VMess",_("Client email")))).modalonly=!0,o.depends("protocol","vmess"),(o=d.taboption("general",form.Value,"s_vmess_client_user_level","%s - %s".format("VMess",_("Client User level")))).modalonly=!0,o.depends("protocol","vmess"),o.datatype="uinteger",(o=d.taboption("general",form.Value,"s_vmess_default_alter_id","%s - %s".format("VMess",_("Default alter ID")))).modalonly=!0,o.depends("protocol","vmess"),o.datatype="and(min(0), max(65535))",(o=d.taboption("general",form.Value,"s_vmess_default_user_level","%s - %s".format("VMess",_("Default user level")))).modalonly=!0,o.depends("protocol","vmess"),o.datatype="uinteger",(o=d.taboption("general",form.Value,"s_vmess_detour_to","%s - %s".format("VMess",_("Detour to")),_("Optional feature to suggest client to take a detour. If specified, this inbound will instruct the outbound to use another inbound."))).modalonly=!0,o.depends("protocol","vmess"),(o=d.taboption("general",form.Flag,"s_vmess_disable_insecure_encryption","%s - %s".format("VMess",_("Disable insecure encryption")))).modalonly=!0,o.depends("protocol","vmess"),(o=d.taboption("stream",form.ListValue,"ss_network",_("Network"))).value(""),o.value("tcp","TCP"),o.value("kcp","mKCP"),o.value("ws","WebSocket"),o.value("http","HTTP/2"),o.value("domainsocket","Domain Socket"),o.value("quic","QUIC"),(o=d.taboption("stream",form.ListValue,"ss_security",_("Security"))).modalonly=!0,o.value(""),o.value("none",_("None")),o.value("tls","TLS"),(o=d.taboption("stream",form.Value,"ss_tls_server_name","%s - %s".format("TLS",_("Server name")))).modalonly=!0,o.depends("ss_security","tls"),o.datatype="host",(o=d.taboption("stream",form.Value,"ss_tls_alpn","%s - %s".format("TLS","ALPN"))).modalonly=!0,o.depends("ss_security","tls"),o.placeholder="http/1.1",(o=d.taboption("stream",form.Flag,"ss_tls_allow_insecure","%s - %s".format("TLS",_("Allow insecure")))).modalonly=!0,o.depends("ss_security","tls"),(o=d.taboption("stream",form.Flag,"ss_tls_allow_insecure_ciphers","%s - %s".format("TLS",_("Allow insecure ciphers")))).modalonly=!0,o.depends("ss_security","tls"),(o=d.taboption("stream",form.Flag,"ss_tls_disable_system_root","%s - %s".format("TLS",_("Disable system root")))).modalonly=!0,o.depends("ss_security","tls"),(o=d.taboption("stream",form.ListValue,"ss_tls_cert_usage","%s - %s".format("TLS",_("Certificate usage")))).modalonly=!0,o.depends("ss_security","tls"),o.value(""),o.value("encipherment"),o.value("verify"),o.value("issue"),(o=d.taboption("stream",form.Value,"ss_tls_cert_fiile","%s - %s".format("TLS",_("Certificate file")))).modalonly=!0,o.depends("ss_security","tls"),(o=d.taboption("stream",form.Value,"ss_tls_key_file","%s - %s".format("TLS",_("Key file")))).modalonly=!0,o.depends("ss_security","tls"),(o=d.taboption("stream",form.ListValue,"ss_tcp_header_type","%s - %s".format("TCP",_("Header type")))).modalonly=!0,o.depends("ss_network","tcp"),o.value(""),o.value("none",_("None")),o.value("http","HTTP"),(o=d.taboption("stream",form.Value,"ss_tcp_header_request_version","%s - %s".format("TCP",_("HTTP request version")))).modalonly=!0,o.depends("ss_tcp_header_type","http"),o.placeholder="1.1",(o=d.taboption("stream",form.ListValue,"ss_tcp_header_request_method","%s - %s".format("TCP",_("HTTP request method")))).modalonly=!0,o.depends("ss_tcp_header_type","http"),o.value(""),o.value("GET"),o.value("HEAD"),o.value("POST"),o.value("DELETE"),o.value("PUT"),o.value("PATCH"),o.value("OPTIONS"),o.default="GET",(o=d.taboption("stream",form.Value,"ss_tcp_header_request_path","%s - %s".format("TCP",_("Request path")))).modalonly=!0,o.depends("ss_tcp_header_type","http"),(o=d.taboption("stream",form.DynamicList,"ss_tcp_header_request_headers","%s - %s".format("TCP",_("Request headers")),_("A list of HTTP headers, format: <code>header=value</code>. eg: %s").format("Host=www.bing.com"))).modalonly=!0,o.depends("ss_tcp_header_type","http"),(o=d.taboption("stream",form.Value,"ss_tcp_header_response_version","%s - %s".format("TCP",_("HTTP response version")))).modalonly=!0,o.depends("ss_tcp_header_type","http"),o.placeholder="1.1",(o=d.taboption("stream",form.Value,"ss_tcp_header_response_status","%s - %s".format("TCP",_("HTTP response status")))).modalonly=!0,o.depends("ss_tcp_header_type","http"),o.placeholder="200",(o=d.taboption("stream",form.Value,"ss_tcp_header_response_reason","%s - %s".format("TCP",_("HTTP response reason")))).modalonly=!0,o.depends("ss_tcp_header_type","http"),o.placeholder="OK",(o=d.taboption("stream",form.DynamicList,"ss_tcp_header_response_headers","%s - %s".format("TCP",_("Response headers")),_("A list of HTTP headers, format: <code>header=value</code>. eg: %s").format("Host=www.bing.com"))).modalonly=!0,o.depends("ss_tcp_header_type","http"),(o=d.taboption("stream",form.Value,"ss_kcp_mtu","%s - %s".format("mKCP",_("Maximum transmission unit (MTU)")))).modalonly=!0,o.depends("ss_network","kcp"),o.datatype="and(min(576), max(1460))",o.placeholder="1350",(o=d.taboption("stream",form.Value,"ss_kcp_tti","%s - %s".format("mKCP",_("Transmission time interval (TTI)")))).modalonly=!0,o.depends("ss_network","kcp"),o.datatype="and(min(10), max(100))",o.placeholder="50",(o=d.taboption("stream",form.Value,"ss_kcp_uplink_capacity","%s - %s".format("mKCP",_("Uplink capacity")))).modalonly=!0,o.depends("ss_network","kcp"),o.datatype="uinteger",o.placeholder="5",(o=d.taboption("stream",form.Value,"ss_kcp_downlink_capacity","%s - %s".format("mKCP",_("Downlink capacity")))).modalonly=!0,o.depends("ss_network","kcp"),o.datatype="uinteger",o.placeholder="20",(o=d.taboption("stream",form.Flag,"ss_kcp_congestion","%s - %s".format("mKCP",_("Congestion enabled")))).modalonly=!0,o.depends("ss_network","kcp"),(o=d.taboption("stream",form.Value,"ss_kcp_read_buffer_size","%s - %s".format("mKCP",_("Read buffer size")))).modalonly=!0,o.depends("ss_network","kcp"),o.datatype="uinteger",o.placeholder="2",(o=d.taboption("stream",form.Value,"ss_kcp_write_buffer_size","%s - %s".format("mKCP",_("Write buffer size")))).modalonly=!0,o.depends("ss_network","kcp"),o.datatype="uinteger",o.placeholder="2",(o=d.taboption("stream",form.ListValue,"ss_kcp_header_type","%s - %s".format("mKCP",_("Header type")))).modalonly=!0,o.depends("ss_network","kcp"),o.value(""),o.value("none",_("None")),o.value("srtp","SRTP"),o.value("utp","uTP"),o.value("wechat-video",_("Wechat Video")),o.value("dtls","DTLS 1.2"),o.value("wireguard","WireGuard"),(o=d.taboption("stream",form.Value,"ss_websocket_path","%s - %s".format("WebSocket",_("Path")))).modalonly=!0,o.depends("ss_network","ws"),(o=d.taboption("stream",form.DynamicList,"ss_websocket_headers","%s - %s".format("WebSocket",_("Headers")),_("A list of HTTP headers, format: <code>header=value</code>. eg: %s").format("Host=www.bing.com"))).modalonly=!0,o.depends("ss_network","ws"),(o=d.taboption("stream",form.DynamicList,"ss_http_host","%s - %s".format("HTTP/2",_("Host")))).modalonly=!0,o.depends("ss_network","http"),(o=d.taboption("stream",form.Value,"ss_http_path","%s - %s".format("HTTP/2",_("Path")))).modalonly=!0,o.depends("ss_network","http"),o.placeholder="/",(o=d.taboption("stream",form.Value,"ss_domainsocket_path","%s - %s".format("Domain Socket",_("Path")))).modalonly=!0,o.depends("ss_network","domainsocket"),(o=d.taboption("stream",form.ListValue,"ss_quic_security","%s - %s".format("QUIC",_("Security")))).modalonly=!0,o.depends("ss_network","quic"),o.value(""),o.value("none",_("None")),o.value("aes-128-gcm"),o.value("chacha20-poly1305"),(o=d.taboption("stream",form.Value,"ss_quic_key","%s - %s".format("QUIC",_("Key")))).modalonly=!0,o.depends("ss_quic_security","aes-128-gcm"),o.depends("ss_quic_security","chacha20-poly1305"),(o=d.taboption("stream",form.ListValue,"ss_quic_header_type","%s - %s".format("QUIC",_("Header type")))).modalonly=!0,o.depends("ss_network","quic"),o.value(""),o.value("none",_("None")),o.value("srtp","SRTP"),o.value("utp","uTP"),o.value("wechat-video",_("Wechat Video")),o.value("dtls","DTLS 1.2"),o.value("wireguard","WireGuard"),(o=d.taboption("stream",form.ListValue,"ss_sockopt_tcp_fast_open","%s - %s".format(_("Sockopt"),_("TCP fast open")))).modalonly=!0,o.value(""),o.value("0",_("False")),o.value("1",_("True")),(o=d.taboption("stream",form.ListValue,"ss_sockopt_tproxy","%s - %s".format(_("Sockopt"),_("TProxy")),_("If transparent proxy enabled on current inbound, this option will be ignored."))).modalonly=!0,o.value(""),o.value("redirect","Redirect"),o.value("tproxy","TProxy"),o.value("off",_("Off")),(o=d.taboption("other",form.Value,"tag",_("Tag"))).rmempty=!1,(o=d.taboption("other",form.Flag,"sniffing_enabled","%s - %s".format(_("Sniffing"),_("Enabled")))).modalonly=!0,(o=d.taboption("other",form.MultiValue,"sniffing_dest_override","%s - %s".format(_("Sniffing"),_("Dest override")))).modalonly=!0,o.value("fakedns"),o.value("http"),o.value("tls"),o.value("quic"),o.value("fakedns+others"),(o=d.taboption("other",form.ListValue,"metadata_only",_("Metadata Only"))).modalonly=!0,o.value("0",_("False")),o.value("1",_("True")),(o=d.taboption("other",form.DynamicList,"domains_excluded",_("Domains Excluded"))).modalonly=!0,o.datatype="hostname",(o=d.taboption("other",form.Flag,"route_only",_("Route Only"))).modalonly=!0,(o=d.taboption("other",form.ListValue,"allocate_strategy","%s - %s".format(_("Allocate"),_("Strategy")))).modalonly=!0,o.value(""),o.value("always"),o.value("random"),(o=d.taboption("other",form.Value,"allocate_refresh","%s - %s".format(_("Allocate"),_("Refresh")))).modalonly=!0,o.datatype="uinteger",(o=d.taboption("other",form.Value,"allocate_concurrency","%s - %s".format(_("Allocate"),_("Concurrency")))).modalonly=!0,o.datatype="uinteger",n.render()}});