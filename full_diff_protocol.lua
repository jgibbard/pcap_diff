-- There is not a nice list of these mappings anywhere, and there is no API
-- in Wireshark to set the link type from an uint, so you must call a dissector
-- by its name.
-- Below are the most common ones taken from the Wireshark source code.
local dlt_dissectors = {
    -- Ethernet and IP
    [1]   = "eth_withoutfcs",    -- DLT_EN10MB (Ethernet)
    [228] = "ipv4",              -- DLT_IPV4
    [229] = "ipv6",              -- DLT_IPV6
    -- WiFi
    [105] = "ieee80211",         -- DLT_IEEE802_11
    [119] = "prism",             -- DLT_PRISM_HEADER
    [127] = "radiotap",          -- DLT_IEEE802_11_RADIO
    [163] = "wlancap",           -- DLT_IEEE802_11_RADIO_AVS
    -- PPP
    [9]   = "ppp",               -- DLT_PPP
    [50]  = "ppp_hdlc",          -- DLT_PPP_HDLC
    [51]  = "pppoes",            -- DLT_PPP_ETHER
    -- USB
    [186] = "usb_freebsd",       -- DLT_USB_FREEBSD
    [189] = "usb_linux",         -- DLT_USB_LINUX
    [148] = "usb_linux_mmapped", -- DLT_USB_LINUX_MMAPPED
    [249] = "usb_win32",         -- DLT_USBPCAP
    [266] = "usb_darwin",        -- DLT_USB_DARWIN
    [288] = "usbll",             -- DLT_USB_2_0
    [293] = "usbll.low_speed",   -- DLT_USB_2_0_LOW_SPEED
    [294] = "usbll.full_speed",  -- DLT_USB_2_0_FULL_SPEED
    [295] = "usbll.high_speed",  -- DLT_USB_2_0_HIGH_SPEED
    -- Bluetooth
    [187] = "bluetooth",         -- DLT_BLUETOOTH_HCI_H4
    [201] = "bluetooth",         -- DLT_BLUETOOTH_HCI_H4_WITH_PHDR
    [251] = "bluetooth",         -- DLT_BLUETOOTH_LE_LL    
    [254] = "bluetooth.btmon",   -- DLT_BLUETOOTH_LINUX_MONITOR
    [255] = "bluetooth",         -- DLT_BLUETOOTH_BREDR_BB
    [256] = "bluetooth",         -- DLT_BLUETOOTH_LE_LL_WITH_PHDR
    [272] = "nordic_ble",        -- DLT_NORDIC_BLE
    -- 802.15.4
    [191] = "wpan",              -- DLT_IEEE802_15_4
    [195] = "wpan",              -- DLT_IEEE802_15_4_WITHFCS
    [215] = "wpan-nonask-phy",   -- DLT_IEEE802_15_4_NONASK_PHY
    [230] = "wpan_nofcs",        -- DLT_IEEE802_15_4_NOFCS    
    [283] = "wpan-tap",          -- DLT_IEEE802_15_4_TAP
    -- Other
    [0]   = "null",              -- DLT_NULL (BSD loopback)
    [3]   = "ax25",              -- DLT_AX25
    [113] = "sll_v1",            -- DLT_LINUX_SLL
    [276] = "sll_v2"             -- DLT_LINUX_SLL2
}

diff_protocol = Proto("diff", "Diff Protocol")

local match_type_field = ProtoField.uint8(
    "diff.match_type", "Match Type", base.DEC, {
        [0] = "Matched",
        [1] = "Removed",
        [2] = "Added"
    })

local ll_type_field = ProtoField.uint32(
    "diff.link_type", "Link Layer Type", base.DEC, nil, nil, "PCAP Link Layer Type")

local payload_field = ProtoField.bytes("diff.payload", "Payload")

diff_protocol.fields = { match_type_field, ll_type_field, payload_field }

function diff_protocol.dissector(buffer, pinfo, tree)

    if buffer:len() < 5 then return 0 end

    pinfo.cols.protocol = diff_protocol.name

    local subtree = tree:add(diff_protocol, buffer(), "Diff Protocol")

    subtree:add(match_type_field, buffer(0,1))

    local ll_value = buffer(1,4):le_uint()
    subtree:add_le(ll_type_field, buffer(1,4))

    local payload = buffer(5):tvb()
    subtree:add(payload_field, buffer(5))

    local dissector_name = dlt_dissectors[ll_value]
    if dissector_name then
        Dissector.get(dissector_name):call(payload, pinfo, tree)
    end

end

