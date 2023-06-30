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
"require validation";

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
  domainRule: function (Value: string, hostMapping: boolean = false): boolean {
    const localhostReg = /^localhost$/i;
    const hostReg = /^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$/;
    const geositeReg = /^[a-zA-Z][a-zA-Z!-@.]*[a-zA-Z]$/;
    const keywordReg = /^[a-zA-Z0-9-.]+$/;
    if (hostMapping) {
      if (Value.match(hostReg) || Value.match(localhostReg)) {
        return true;
      } else {
        return false;
      }
    }
    if (Value.match(hostReg)) {
      return true;
    } else {
      if (Value.match(localhostReg)) {
        return true;
      } else {
        const ruleExp = Value.match(/^(\S+):(\S+)$/);
        if (ruleExp) {
          switch (ruleExp[1]) {
            case "domain":
              {
                if (ruleExp[2].match(hostReg)) {
                  return true;
                }
              }
              break;
            case "geosite":
              {
                if (ruleExp[2].match(geositeReg)) {
                  return true;
                }
              }
              break;
            case "regexp":
              {
                if (ruleExp[2].length !== 0) {
                  try {
                    new RegExp(ruleExp[2]);
                    return true;
                  } catch (error) {
                    return false;
                  }
                }
              }
              break;
            case "keyword":
              {
                if (ruleExp[2].match(keywordReg)) {
                  return true;
                }
              }
              break;
            default: {
              return false;
            }
          }
        }
        return false;
      }
    }
  },

  ipRule: function (Value: string, hostMapping: boolean = false): boolean {
    if (hostMapping) {
      const IParray: string[] = Value.split(",");
      for (const IPs of IParray) {
        if (IPs.length > 0) {
          const ip4addr = validation.parseIPv4(IPs);
          const ip6addr = validation.parseIPv6(IPs);
          if (null === ip4addr && null === ip6addr) {
            return false;
          }
        } else {
          return false;
        }
      }
      return true;
    } else {
      const ip4addr = validation.parseIPv4(Value);
      const ip6addr = validation.parseIPv6(Value);
      if (null == ip4addr && null == ip6addr) {
        const cidr: string[] = Value.split("/");
        if (cidr && cidr.length == 2) {
          const ip4addr = validation.parseIPv4(cidr[0]);
          const ip6addr = validation.parseIPv6(cidr[0]);
          if (
            (ip4addr && 0 <= parseInt(cidr[1]) && parseInt(cidr[1]) <= 32) ||
            (ip6addr && 0 <= parseInt(cidr[1]) && parseInt(cidr[1]) <= 128)
          ) {
            return true;
          }
        } else {
          const geoipVal = Value.match(
            /^geoip:[a-zA-Z]{2}[a-zA-Z0-9@!-]*(?<![@!0-9-])$/
          );
          if (geoipVal) {
            //console.log(geoipVal[1])
            //if (geoipVal[1] == "geoip" && geoipVal[2].match(/^[a-zA-Z\!-@.]+[a-zA-Z]$/)) {
            return true;
            //}
          } else {
            return false;
          }
        }
      } else {
        return true;
      }
      return false;
    }
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
        const isValid = [num1, num2, num3].every(
          (num) => num >= 0 && num <= 255
        );
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
      case "hostmapping": {
        const hostMap = input_value.match(/^(\S+)\|(\S+)$/);
        if (hostMap) {
          const domainSection = this.domainRule(hostMap[1]);
          if (domainSection) {
            const domainMap = this.domainRule(hostMap[2], true);
            const ipMap = this.ipRule(hostMap[2], true);
            if (domainMap || ipMap) {
              return true;
            }
          }
        }
        return "%s: %s:\n - %s\n   %s\n   %s\n   %s\n   %s\n - %s\n   %s\n   %s\n   %s"
          .format(
            _("Expecting"),
            "domain_structure|mapping_structure",
            _("valid domain structures:"),
            "subdomain: 'domain:google.com'",
            "keywords: 'keyword:google'",
            "predefined domains: 'geosite:google'",
            "regular expression: 'regexp:\.goo.*\.com'. ",
            _("valid mapping structures:"),
            "IP address: '2001:4860:4860::8844'",
            "IP address array: '8.8.8.8,2001:4860:4860::8888,8.8.4.4'",
            "hostname: 'www.google.com'",
          );
      }
      default: {
        return _("Invalid Input");
      }
    }
  },
});
