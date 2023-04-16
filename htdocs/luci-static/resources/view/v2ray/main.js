/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */
"use strict";"require form";"require fs";"require ui";"require uci";"require v2ray";"require view/v2ray/include/custom as custom";return L.view.extend({handleServiceReload:function(e){return fs.exec("/etc/init.d/v2ray",["reload"]).then(L.bind((function(e,o){0!==o.code&&(ui.addNotification(null,[E("p",_("Reload service failed with code %d").format(o.code)),o.stderr?E("pre",{},[o.stderr]):""]),L.raise("Error","Reload failed"))}),this,e.target)).catch((function(e){ui.addNotification(null,E("p",e.message))}))},load:function(){return uci.load("v2ray").then((function(){var e=uci.get("v2ray","main","core");return e||(e="V2Ray"),Promise.all([v2ray.getSections("inbound"),v2ray.getSections("outbound"),e])}))},render:function(e){var o,r=void 0===e?[]:e,a=r[0],t=void 0===a?[]:a,n=r[1],i=void 0===n?[]:n,l=r[2],s=void 0===l?"":l,d=new form.Map("v2ray","%s - %s".format(s,_("Global Settings")),"<p>%s</p><p>%s</p>".format(_("A platform for building proxies to bypass network restrictions."),_("For more information, please visit: %s").format('<a href="https://www.v2ray.com" target="_blank">https://www.v2ray.com</a>'))),u=d.section(form.NamedSection,"main","v2ray");u.addremove=!1,u.anonymous=!0,u.option(custom.RunningStatus,"_status"),(o=u.option(form.Flag,"enabled",_("Enabled"))).rmempty=!1,(o=u.option(form.Button,"_reload",_("Reload Service"),_("This will restart service when config file changes."))).inputstyle="action reload",o.inputtitle=_("Reload"),o.onclick=L.bind(this.handleServiceReload,this),(o=u.option(form.Value,"v2ray_file",_("V2Ray file"),_("Set the V2Ray executable file path."))).datatype="file",o.placeholder="/usr/bin/v2ray",o.rmempty=!1,(o=u.option(form.Value,"asset_location",_("V2Ray asset location"),_("Directory where geoip.dat and geosite.dat files are, default: same directory as V2Ray file."))).datatype="directory",o.placeholder="/usr/bin",(o=u.option(form.Value,"mem_percentage",_("Memory percentage"),_("The maximum percentage of memory used by V2Ray."))).datatype="and(uinteger, max(100))",o.placeholder="80",(o=u.option(form.Value,"config_file",_("Config file"),_("Use custom config file."))).datatype="file",o.value("",_("None")),(o=u.option(form.Value,"access_log",_("Access log file"))).depends("config_file",""),o.value("/dev/null"),o.value("/var/log/v2ray-access.log"),(o=u.option(form.ListValue,"loglevel",_("Log level"))).depends("config_file",""),o.value("debug",_("Debug")),o.value("info",_("Info")),o.value("warning",_("Warning")),o.value("error",_("Error")),o.value("none",_("None")),o.default="warning",(o=u.option(form.Value,"error_log",_("Error log file"))).value("/dev/null"),o.value("/var/log/v2ray-error.log"),o.depends("loglevel","debug"),o.depends("loglevel","info"),o.depends("loglevel","warning"),o.depends("loglevel","error"),(o=u.option(form.MultiValue,"inbounds",_("Inbounds enabled"))).depends("config_file","");for(var f=0,c=t;f<c.length;f++){var p=c[f];o.value(p.value,p.caption)}(o=u.option(form.MultiValue,"outbounds",_("Outbounds enabled"))).depends("config_file","");for(var v=0,g=i;v<g.length;v++){var m=g[v];o.value(m.value,m.caption)}return(o=u.option(form.Flag,"stats_enabled","%s - %s".format(_("Stats"),_("Enabled")))).depends("config_file",""),(o=u.option(form.Flag,"transport_enabled","%s - %s".format(_("Transport"),_("Enabled")))).depends("config_file",""),(o=u.option(custom.TextValue,"_transport","%s - %s".format(_("Transport"),_("Settings")),_("<code>transport</code> field in top level configuration, JSON string"))).depends("transport_enabled","1"),o.wrap="off",o.rows=5,o.datatype="string",o.filepath="/etc/v2ray/transport.json",o.required=!0,o.isjson=!0,d.render()}});