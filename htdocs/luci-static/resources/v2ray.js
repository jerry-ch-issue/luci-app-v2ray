/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */
"use strict";"require fs";"require network";"require uci";return L.Class.extend({getLocalIPs:function(){return network.getNetworks().then((function(t){for(var r=["127.0.0.1","0.0.0.0","::"],n=0,e=t;n<e.length;n++){var o=e[n],i=o.getIPAddr(),u=o.getIP6Addr();i&&(i=i.split("/")[0])&&r.indexOf(i)<0&&r.push(i),u&&(u=u.split("/")[0])&&r.indexOf(u)<0&&r.push(u)}return r.sort()}))},getSections:function(t,r){return void 0===r&&(r="alias"),uci.load("v2ray").then((function(){var n=[];return uci.sections("v2ray",t,(function(t){var e;(e=t[r])?n.push({caption:e,value:t[".name"]}):n.push({caption:"no_alias",value:t[".name"]})})),n}))},getDokodemoDoorPorts:function(){return uci.load("v2ray").then((function(){var t=[];return uci.sections("v2ray","inbound",(function(r){var n;if("dokodemo-door"==r.protocol&&(n=r.port)){var e;(e=r.alias)?t.push({caption:"%s - %s".format(e,n),value:n}):t.push({caption:"%s:%s".format(r.listen,n),value:n})}})),t}))}});