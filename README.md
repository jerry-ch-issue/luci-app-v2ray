# luci-app-v2ray

Luci support for V2Ray V5 / Xray

**This branch the LuCI for OpenWrt 22.03 and later with firewall4 base on [luci-app-v2ray by kuoruan](https://github.com/kuoruan/luci-app-v2ray/tree/master) .**

**For legacy version: [Branch legacy](https://github.com/kuoruan/luci-app-v2ray/tree/legacy)**

[![Release Version](https://img.shields.io/github/release/kuoruan/luci-app-v2ray.svg)](https://github.com/kuoruan/luci-app-v2ray/releases/latest) [![Latest Release Download](https://img.shields.io/github/downloads/kuoruan/luci-app-v2ray/latest/total.svg)](https://github.com/kuoruan/luci-app-v2ray/releases/latest) [![Total Download](https://img.shields.io/github/downloads/kuoruan/luci-app-v2ray/total.svg)](https://github.com/kuoruan/luci-app-v2ray/releases)

## Install

### Since the key of the opkg repository from kuoruan is no longer available, you will have to instal the ipk files manually


### Manual install

1. Download ipk files from [release](https://github.com/kuoruan/luci-app-v2ray/releases) page

2. Upload files to your router

3. Install package with opkg:

```sh
opkg install luci-app-v2ray_*.ipk
```

Dependencies:

- jshn
- ip (ip-tiny or ip-full)
- nftables-json
- kmod-nft-tproxy
- kmod-nft-socket
- resolveip
- dnsmasq-full v2.87 or later (gfwlist mode needs nft set support)

For translations, please install ```luci-i18n-v2ray-*```.

> You may need to remove ```dnsmasq``` before installing this package.

## Configure

1. Download Core file from V2Ray/Xray release
> [V2Ray](https://github.com/v2fly/v2ray-core/releases)
> [Xray](https://github.com/xtls/xray-core/releases).

2. Upload V2Ray file to your router, or install the ipk file.

3. Config V2Ray file path in LuCI page.

4. Add your inbound and outbound rules.

5. Enable the service via LuCI.

## Build

Package files is in branch [luci2](https://github.com/kuoruan/luci-app-v2ray/tree/luci2)

Download with Git:

```sh
git clone -b luci2 https://github.com/kuoruan/luci-app-v2ray.git luci-app-v2ray
```
