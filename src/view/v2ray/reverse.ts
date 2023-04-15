/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */

"use strict";

"require form";
"require uci";
// "require view";

// @ts-ignore
return L.view.extend<string>({
  load: function () {
    return uci.load("v2ray").then(function () {
      let core = uci.get("v2ray", "main", "core");
      if (!core) {
        core = "V2Ray";
      }
      return core;
    });
  },
  render: function (core = "") {
    const m = new form.Map(
      "v2ray",
      "%s - %s".format(core, _("Reverse")),
      _("Details: %s").format(
        '<a href="https://www.v2ray.com/en/configuration/reverse.html#reverseobject" target="_blank">ReverseObject</a>'
      )
    );

    const s = m.section(form.NamedSection, "main_reverse", "reverse");
    s.addremove = false;

    let o;
    o = s.option(form.Flag, "enabled", _("Enabled"));
    o.rmempty = false;

    o = s.option(
      form.DynamicList,
      "bridges",
      _("Bridges"),
      _("A list of bridges, format: <code>tag|domain</code>. eg: %s").format(
        "bridge|test.v2ray.com"
      )
    );

    o = s.option(
      form.DynamicList,
      "portals",
      _("Portals"),
      _("A list of portals, format: <code>tag|domain</code>. eg: %s").format(
        "portal|test.v2ray.com"
      )
    );

    return m.render();
  },
});
