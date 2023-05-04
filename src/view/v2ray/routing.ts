/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */

"use strict";

"require form";
"require uci";
"require v2ray";
// "require view";

// @ts-ignore
return L.view.extend<SectionItem[][][][][][][][][], string>({
  load: function () {
    return uci.load("v2ray").then(function () {
      let core = uci.get("v2ray", "main", "core");
      if (!core) {
        core = "V2Ray";
      }
      return Promise.all([
        v2ray.getSections("routing_rule"),
        v2ray.getSections("routing_balancer", "tag"),
        v2ray.getSections("inbound", "alias"),
        v2ray.getSections("inbound", "tag"),
        v2ray.getSections("outbound", "alias"),
        v2ray.getSections("outbound", "tag"),
        v2ray.getSections("dns", "tag"),
        v2ray.getSections("reverse", "bridges"),
        v2ray.getSections("reverse", "portals"),
        core,
      ]);
    });
  },
  render: function ([
    routingRules = [],
    routingBalancers = [],
    inbound_alias = [],
    inbound_tag = [],
    outbound_alias = [],
    outbound_tag = [],
    dns_tag = [],
    reverse_bridges = [],
    reverse_portals = [],
    core = "",
  ] = []) {
    const m = new form.Map(
      "v2ray",
      "%s - %s".format(core, _("Routing")),
      _("Details: %s").format(
        '<a href="https://xtls.github.io/config/routing.html#routingobject" target="_blank">RoutingObject</a>'
      )
    );

    const s1 = m.section(form.NamedSection, "main_routing", "routing");
    s1.anonymous = true;
    s1.addremove = false;

    let o;
    o = s1.option(form.Flag, "enabled", _("Enabled"));
    o = s1.option(
      form.ListValue,
      "domain_strategy",
      _("Domain resolution strategy")
    );
    o.value("AsIs");
    o.value("IPIfNonMatch");
    o.value("IPOnDemand");

    o = s1.option(form.ListValue, "main_domain_matcher", _("Domain Matcher"));
    o.value("hybrid");
    o.value("linear");

    o = s1.option(
      form.MultiValue,
      "rules",
      _("Rules"),
      _("Select routing rules to use")
    );
    for (const s of routingRules) {
      o.value(s.value, s.caption);
    }

    o = s1.option(
      form.MultiValue,
      "balancers",
      _("Balancers"),
      _("Select routing balancers to use")
    );
    for (const s of routingBalancers) {
      o.value(s.value, s.caption);
    }

    const s2 = m.section(
      form.GridSection,
      "routing_rule",
      _("Routing Rule"),
      _("Add routing rules here")
    );
    s2.anonymous = false;
    s2.addremove = true;
    s2.sortable = true;
    s2.nodescription = true;

    o = s2.option(form.Value, "alias", _("Alias"));
    o.rmempty = false;

    o = s2.option(form.ListValue, "domain_matcher", _("Domain Matcher"));
    o.value("hybrid");
    o.value("linear");

    o = s2.option(form.ListValue, "type", _("Type"));
    o.value("field");

    o = s2.option(form.DynamicList, "domain", _("Domain"));
    o.modalonly = true;

    o = s2.option(form.DynamicList, "ip", _("IP"));
    o.modalonly = true;

    o = s2.option(form.DynamicList, "port", _("Port"));
    o.modalonly = true;
    o.datatype = "or(port, portrange)";

    o = s2.option(form.MultiValue, "network", _("Network"));
    o.value("tcp");
    o.value("udp");

    o = s2.option(form.DynamicList, "source", _("Source"));
    o.modalonly = true;
    o.datatype = "ipaddr";

    o = s2.option(form.DynamicList, "source_port", _("Source Port"));
    o.modalonly = true;
    o.datatype = "or(port, portrange)";

    o = s2.option(form.DynamicList, "user", _("User"));
    o.modalonly = true;

    o = s2.option(form.MultiValue, "inbound_tag", _("Inbound Tag"));
    o.value(dns_tag[0].caption, `DNS(${dns_tag[0].caption})`);
    for (let i = 0; i < inbound_alias.length; i++) {
      o.value(
        inbound_tag[i].caption,
        `${inbound_alias[i].caption}(${inbound_tag[i].caption})`
      );
    }
    for (const rb of reverse_bridges) {
      const stmp = String(rb.caption);
      const cap = stmp.split(",");
      for (const rba of cap) {
        o.value(rba.substring(0, rba.indexOf("|")), rba);
      }
    }
    o = s2.option(form.MultiValue, "protocol", _("Protocol"));
    o.modalonly = true;
    o.value("http");
    o.value("tls");
    o.value("bittorrent");

    o = s2.option(form.Value, "attrs", _("Attrs"));
    o.modalonly = true;

    o = s2.option(form.ListValue, "outbound_tag", _("Outbound tag"));
    for (let i = 0; i < outbound_alias.length; i++) {
      o.value(
        outbound_tag[i].caption,
        `${outbound_alias[i].caption}(${outbound_tag[i].caption})`
      );
    }
    for (const rp of reverse_portals) {
      const stmp = String(rp.caption);
      const cap = stmp.split(",");
      for (const rpa of cap) {
        o.value(rpa.substring(0, rpa.indexOf("|")), rpa);
      }
    }
    o = s2.option(form.Value, "balancer_tag", _("Balancer tag"));
    o.modalonly = true;
    o.depends("outbound_tag", "");

    const s3 = m.section(
      form.TypedSection,
      "routing_balancer",
      _("Routing Balancer", _("Add routing balancers here"))
    );
    s3.anonymous = true;
    s3.addremove = true;

    o = s3.option(form.Value, "tag", _("Tag"));
    o.rmempty = false;

    o = s3.option(form.DynamicList, "selector", _("Selector"));

    return m.render();
  },
});