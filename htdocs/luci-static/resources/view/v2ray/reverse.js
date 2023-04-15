/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */
"use strict";"require form";return L.view.extend({load:function(){return uci.load("v2ray").then((function(){var e=uci.get("v2ray","main","core");return e||(e="V2Ray"),e}))},render:function(e){var r=new form.Map("v2ray","%s - %s".format(e,_("Reverse")),_("Details: %s").format('<a href="https://www.v2ray.com/en/configuration/reverse.html#reverseobject" target="_blank">ReverseObject</a>')),t=r.section(form.NamedSection,"main_reverse","reverse");return t.addremove=!1,t.option(form.Flag,"enabled",_("Enabled")).rmempty=!1,t.option(form.DynamicList,"bridges",_("Bridges"),_("A list of bridges, format: <code>tag|domain</code>. eg: %s").format("bridge|test.v2ray.com")),t.option(form.DynamicList,"portals",_("Portals"),_("A list of portals, format: <code>tag|domain</code>. eg: %s").format("portal|test.v2ray.com")),r.render()}});