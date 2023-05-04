/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */

"use strict";

"require fs";
"require uci";
"require ui";
// "require view";

// @ts-ignore
return L.view.extend<[string, string, string]>({
  load: function () {
    return uci.load("v2ray").then(function () {
      let configFile = uci.get("v2ray", "main", "config_file");
      let core = uci.get("v2ray", "main", "core");
      if (!core) {
        core = "V2Ray";
      }
      if (!configFile) {
        configFile = "/var/etc/v2ray/v2ray.main.json";
      }
      return Promise.all([
        Promise.resolve(configFile),
        L.resolveDefault(fs.read(configFile), ""),
        core,
      ]);
    });
  },
  render: function ([configFile = "", configContent = "", core = ""] = []) {
    return E([
      E("h2", "%s - %s".format(core, _("About"))),
      E("p", _("LuCI support for V2Ray v5 and Xray 1.8.0.")),
      E(
        "p",
        _("Version: %s").format(
          `${process.env.LUCI_VERSION}-${process.env.LUCI_RELEASE}`
        )
      ),
      E("p", _("Author: %s").format("Xingwang Liao")),
      E(
        "p",
        _("Source: %s").format(
          '<a href="https://github.com/kuoruan/luci-app-v2ray" target="_blank">https://github.com/kuoruan/luci-app-v2ray</a>'
        )
      ),
      E(
        "p",
        _("Latest: %s").format(
          '<a href="https://github.com/kuoruan/luci-app-v2ray/releases/latest" target="_blank">https://github.com/kuoruan/luci-app-v2ray/releases/latest</a>'
        )
      ),
      E(
        "p",
        _("Report Bugs: %s").format(
          '<a href="https://github.com/kuoruan/luci-app-v2ray/issues" target="_blank">https://github.com/kuoruan/luci-app-v2ray/issues</a>'
        )
      ),
      E(
        "p",
        _("Donate: %s").format(
          '<a href="https://blog.kuoruan.com/donate" target="_blank">https://blog.kuoruan.com/donate</a>'
        )
      ),
      E("p", _("Current Config File: %s").format(configFile)),
      E(
        "pre",
        {
          style:
            "-moz-tab-size: 4;-o-tab-size: 4;tab-size: 4;word-break: break-all;",
        },
        configContent ? configContent : _("Failed to open file.")
      ),
    ]);
  },
  handleReset: null,
  handleSave: null,
  handleSaveApply: null,
});