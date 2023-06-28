/**
 * @license
 * Copyright 2020 Xingwang Liao <kuoruan@gmail.com>
 *
 * Licensed to the public under the MIT License.
 */

"use strict";

// "require baseclass";
"require fs";
"require network";
"require uci";

// @ts-ignore
return L.Class.extend({
  getLocalIPs: function (): Promise<string[]> {
    return network.getNetworks().then(function (networks: network.Protocol[]) {
      const localIPs: string[] = ["127.0.0.1", "0.0.0.0", "::"];

      for (const n of networks) {
        let IPv4 = n.getIPAddr();
        let IPv6 = n.getIP6Addr();

        if (IPv4 && (IPv4 = IPv4.split("/")[0]) && localIPs.indexOf(IPv4) < 0) {
          localIPs.push(IPv4);
        }

        if (IPv6 && (IPv6 = IPv6.split("/")[0]) && localIPs.indexOf(IPv6) < 0) {
          localIPs.push(IPv6);
        }
      }

      return localIPs.sort();
    });
  },

  getCore: function (): string {
    return uci.load("v2ray").then(function () {
      let core: string = uci.get("v2ray", "main", "core");
      if (!core) {
        core = "V2Ray";
      }
    });
  },

  getSections: function (
    type: string,
    captionKey: string = "alias"
  ): Promise<SectionItem[]> {
    return uci.load("v2ray").then(function () {
      const sections: SectionItem[] = [];

      uci.sections("v2ray", type, function (s: uci.SectionObject) {
        const caption: string = s[captionKey];
        if (caption) {
          sections.push({
            caption: caption,
            value: s[".name"],
          });
        }
      });
      return sections;
    });
  },

  getDokodemoDoorPorts: function (): Promise<SectionItem[]> {
    return uci.load("v2ray").then(function () {
      const sections: SectionItem[] = [];

      uci.sections("v2ray", "inbound", function (s: uci.SectionObject) {
        let port: string;
        if (s["protocol"] == "dokodemo-door" && (port = s["port"])) {
          let alias: string;

          if ((alias = s["alias"])) {
            sections.push({
              caption: "%s - %s".format(alias, port),
              value: port,
            });
          } else {
            sections.push({
              caption: "%s:%s".format(s["listen"], port),
              value: port,
            });
          }
        }
      });

      return sections;
    });
  },

  getXtlsSecurity: function (): Promise<tlsItem[]> {
    return uci.load("v2ray").then(function () {
      const xtls: xtlsItem[] = [];

      uci.sections("v2ray", "v2ray", function (s: uci.SectionObject) {
        if (s["core"] == "Xray") {
          if (s["reality"] == "1") {
            xtls.push({
              security: ["reality|REALITY"],
              flow: ["xtls-rprx-vision", "xtls-rprx-vision-udp443"],
            });
          } else {
            xtls.push({
              security: ["xtls|XTLS"],
              flow: [
                "xtls-rprx-direct",
                "xtls-rprx-direct-udp443",
                "xtls-rprx-origin",
                "xtls-rprx-origin-udp443",
                "xtls-rprx-splice",
                "xtls-rprx-splice-udp443",
              ],
            });
          }
        }
      });
      return xtls;
    });
  },

  v2rayValidation: function (
    validate_type: string,
    input_value: string
  ): boolean | string {
    switch (validate_type) {
      case "wg-keys": {
        if (
          input_value.match("^[a-zA-Z0-9/+]+=?=?$") !== null &&
          input_value.length % 4 === 0 &&
          input_value.length === 44
        ) {
          return true;
        }
        return _("Invalid WireGuard key");
      }
      case "wg-reserved": {
        const regex = /^(\d{1,3}),(\d{1,3}),(\d{1,3})$/;
        const match = input_value.match(regex);
        if (!match) {
          return "%s:\n- %s\n  %s".format(
            _("Expecting"),
            _("'value1,value2,value3'"),
            _("each value should be an integer between 0-255")
          );
        }
        const [, num1, num2, num3] = match.map(Number);
        const isValid = [num1, num2, num3].every((num) => num >= 0 && num <= 255);
        return isValid
          ? true
          : "%s:\n- %s\n  %s".format(
              _("Expecting"),
              _("'value1,value2,value3'"),
              _("each value should be an integer between 0-255")
            );
      }
      case "fragment-length": {
        if (/^\d+$/.test(input_value) && parseInt(input_value) > 0) {
          return true;
        }
        const frag_length: string[] = input_value.split("-");
        const lengthMin: number = parseInt(frag_length[0]);
        const lengthMax: number = parseInt(frag_length[1]);
        if (lengthMin > 0 && lengthMax > lengthMin) {
          return true;
        }
        return "%s: %s:\n- %s\n- %s".format(
          _("Expecting"),
          _("One of the following"),
          _("Integers greater than 0"),
          _("A range of integers which are greater than 0")
        );
      }
      case "fragment-interval": {
        if (/^\d+$/.test(input_value) && parseInt(input_value) > 0) {
          return true;
        }
        if (/^\d+-\d+$/.test(input_value)) {
          const frag_interval: string[] = input_value.split("-");
          const intervalMin: number = parseInt(frag_interval[0]);
          const intervalMax: number = parseInt(frag_interval[1]);
          if (intervalMin > 0 && intervalMax > intervalMin) {
            return true;
          }
        }
        return "%s: %s:\n- %s\n- %s".format(
          _("Expecting"),
          _("One of the following"),
          _("Integers greater than 0"),
          _("A range of integers which are greater than 0")
        );
      }
      case "fragment-packets": {
        if (/^\d+$/.test(input_value) && parseInt(input_value) > 0) {
          return true;
        }
        if (/^\d+-\d+$/.test(input_value)) {
          const packets: string[] = input_value.split("-");
          const start: number = parseInt(packets[0]);
          const end: number = parseInt(packets[1]);
          if (start > 0 && end > start) {
            return true;
          }
        }
        if (input_value === "tlshello") {
          return true;
        }
        return "%s: %s:\n - %s\n   %s\n - %s\n   %s".format(
          _("Expecting"),
          _("One of the following"),
          _("Integers greater than 0, corresponding to the packet index"),
          _("eg: '5' for the fifth packet'"),
          _("A range of integers which are greater than 0"),
          _("eg: '1-3' for the 1st to 3rd packets")
        );
      }
      default: {
        return _("Unknown Data");
      }
    }
  }
});
