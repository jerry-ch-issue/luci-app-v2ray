/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */
"use strict";"require form";"require uci";"require v2ray";"require view/v2ray/include/custom as custom";return L.view.extend({load:function(){return Promise.all([v2ray.getSections("routing_rule"),v2ray.getSections("routing_balancer","tag"),v2ray.getSections("inbound"),v2ray.getSections("inbound","tag"),v2ray.getSections("outbound"),v2ray.getSections("outbound","tag"),v2ray.getSections("dns","tag"),v2ray.getSections("reverse","bridges"),v2ray.getSections("reverse","portals"),v2ray.getCore()])},render:function(o){var t,a=void 0===o?[]:o,e=a[0],r=void 0===e?[]:e,n=a[1],i=void 0===n?[]:n,l=a[2],u=void 0===l?[]:l,d=a[3],c=void 0===d?[]:d,s=a[4],m=void 0===s?[]:s,v=a[5],g=void 0===v?[]:v,p=a[6],y=void 0===p?[]:p,f=a[7],b=void 0===f?[]:f,h=a[8],S=void 0===h?[]:h,D=a[9],V=void 0===D?"":D,L=new form.Map("v2ray","%s - %s".format(V,_("Routing")),_("Details: %s").format('<a href="https://xtls.github.io/config/routing.html#routingobject" target="_blank">RoutingObject</a>')),M=L.section(form.NamedSection,"main_routing","routing");M.anonymous=!0,M.addremove=!1,t=M.option(form.Flag,"enabled",_("Enabled")),(t=M.option(form.ListValue,"domain_strategy",_("Domain Matching Strategy"))).optional=!1,t.value("AsIs"),t.value("IPIfNonMatch"),t.value("IPOnDemand"),(t = M.option(form.MultiValue, "main_domain_matcher", _("Domain Matcher"))).value("mph"),t.value("linear"),t=M.option(form.MultiValue,"rules",_("Rules"),_("Select routing rules to use"));for(var R=0,P=r;R<P.length;R++){var A=P[R];t.value(A.value,A.caption)}t=M.option(form.MultiValue,"balancers",_("Balancers"),_("Select routing balancers to use"));for(var I=0,w=i;I<w.length;I++){A=w[I];t.value(A.value,A.caption)}var O=L.section(form.GridSection,"routing_rule",_("Routing Rule"),_("Add routing rules here"));O.sectiontitle=function(o){return uci.get("v2ray",o,"alias")},O.addremove=!0,O.sortable=!0,O.nodescription=!0,O.modaltitle=function(o){var t=uci.get("v2ray",o,"alias");return _("Routing Rule")+" > "+(null!=t?t:_("Add"))},(t=O.option(form.Value,"alias",_("Alias"))).rmempty=!1,t.modalonly=!0,(t = O.option(form.MultiValue,"domain_matcher",_("Domain Matcher"))).value("mph"),t.value("linear"),t.modalonly=!0,(t=O.option(form.ListValue,"type",_("Type"))).value("field"),t.modalonly=!0,(t=O.option(form.DynamicList,"domain",_("Domain"))).modalonly=!0,t.validate=function(o,t){return!t||v2ray.v2rayValidation("domainrule",t)},(t=O.option(form.DynamicList,"ip",_("IP"))).modalonly=!0,t.validate=function(o,t){return!t||v2ray.v2rayValidation("iprule",t)},(t=O.option(form.DynamicList,"port",_("Port"))).modalonly=!0,t.datatype="or(port, portrange)",(t=O.option(form.MultiValue,"network",_("Network"))).value("tcp"),t.value("udp"),(t=O.option(form.DynamicList,"source",_("Source"))).modalonly=!0,t.datatype="or(ipaddr, cidr)",(t=O.option(form.DynamicList,"source_port",_("Source Port"))).modalonly=!0,t.datatype="or(port, portrange)",(t=O.option(form.DynamicList,"user",_("User"))).modalonly=!0,(t=O.option(form.MultiValue,"inbound_tag",_("Inbound Tag"))).value(y[0].caption,"DNS("+y[0].caption+")");for(var q=0;q<u.length;q++)t.value(c[q].caption,u[q].caption+"("+c[q].caption+")");for(var x=0,N=b;x<N.length;x++)for(var T=N[x],k=0,B=String(T.caption).split(",");k<B.length;k++){var j=B[k];t.value(j.substring(0,j.indexOf("|")),j)}(t=O.option(form.MultiValue,"protocol",_("Protocol"))).modalonly=!0,t.value("http"),t.value("tls"),t.value("bittorrent"),(t=O.option(form.DynamicList,"attrs",_("Attrs"))).modalonly=!0,t=O.option(form.ListValue,"outbound_tag",_("Outbound tag"));for(q=0;q<m.length;q++)t.value(g[q].caption,m[q].caption+"("+g[q].caption+")");for(var C=0,E=S;C<E.length;C++)for(var F=E[C],G=0,U=String(F.caption).split(",");G<U.length;G++){var z=U[G];t.value(z.substring(0,z.indexOf("|")),z)}(t=O.option(form.Value,"balancer_tag",_("Balancer tag"))).modalonly=!0,t.depends("outbound_tag","");var H=L.section(form.TypedSection,"routing_balancer",_("Routing Balancer",_("Add routing balancers here")));return H.anonymous=!0,H.addremove=!0,(t=H.option(form.Value,"tag",_("Tag"))).rmempty=!1,t=H.option(form.DynamicList,"selector",_("Selector")),L.render()}});
