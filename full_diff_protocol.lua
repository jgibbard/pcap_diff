-- This Wireshark plugin handles parsing a custom link layer protocol that 
-- allows the full diff between two PCAPs to be examined.
-- The protocol allows the two compared PCAPs to have a different link layer.
-- A look up table is used to handover the parsing of the protocol to the 
-- correct link layer.

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

local ll_type_a_field = ProtoField.uint32(
    "diff.link_type", "PCAP A Link Layer Type",
    base.DEC, nil, nil, "PCAP A Link Layer Type")

local ll_type_b_field = ProtoField.uint32(
    "diff.link_type", "PCAP B Link Layer Type",
    base.DEC, nil, nil, "PCAP B Link Layer Type")

local pcap_a_len_field = ProtoField.uint32(
    "diff.pcap_a_len", "PCAP A Payload Length",
    base.DEC, nil, nil, "PCAP A Payload Length")

local pcap_b_len_field = ProtoField.uint32(
    "diff.pcap_b_len", "PCAP B Payload Length",
    base.DEC, nil, nil, "PCAP B Payload Length")

local pcap_b_timestamp_field = ProtoField.absolute_time(
    "diff.pcap_b_timestamp", "PCAP B Timestamp")

local pcap_time_diff_field = ProtoField.relative_time(
    "diff.time_diff", "Time Difference A -> B")

diff_protocol.fields = { match_type_field, ll_type_a_field, ll_type_b_field,
                         pcap_a_len_field, pcap_b_len_field,
                         pcap_b_timestamp_field, pcap_time_diff_field }

function diff_protocol.dissector(buffer, pinfo, tree)

    if buffer:len() < 5 then return 0 end

    pinfo.cols.protocol = diff_protocol.name

    local subtree = tree:add(diff_protocol, buffer(), "Diff Protocol")

    local match = buffer(0,1):le_uint()
    subtree:add(match_type_field, buffer(0,1))

    if match == 0 then  -- Matched
        if buffer:len() < 13 then return 0 end

        local ll_a_value = buffer(1,4):le_uint()
        subtree:add_le(ll_type_a_field, buffer(1,4))

        local a_len = buffer(5,4):le_uint()
        subtree:add_le(pcap_a_len_field, buffer(5,4))
    
        local payload_a = buffer(9, a_len):tvb()
       
        local subtree_a = tree:add(diff_protocol, buffer(9, a_len), "PCAP A")

        local dissector_name_a = dlt_dissectors[ll_a_value]
        if dissector_name_a then
            Dissector.get(dissector_name_a):call(payload_a, pinfo, tree)
        end

        local b_index = 9 + a_len
        local ll_b_value = buffer(b_index, 4):le_uint()
        subtree:add_le(ll_type_b_field, buffer(b_index, 4))
        b_index = b_index + 4

        -- Get Timestamp for PCAP B
        local timestamp_secs = buffer(b_index, 4):le_uint()
        local timestamp_usecs = buffer(b_index + 4, 4):le_uint()
        local ts = NSTime.new(timestamp_secs, timestamp_usecs * 1000)
        subtree:add(pcap_b_timestamp_field, ts)

        -- For some reason there is no way to get the packet timestamp as
        -- as NSTime object - only as floating point seconds. This is therefore
        -- slightly lossy, and there will be small timing errors.
        local pkt_time = NSTime(
                pinfo.abs_ts, select(2,math.modf(pinfo.abs_ts)) * 10^9)
        local time_diff = ts - pkt_time
        subtree:add(pcap_time_diff_field, time_diff)

        b_index = b_index + 8

        local payload_b = buffer(b_index):tvb()
        subtree:add(pcap_b_len_field, payload_b:len())
        local dissector_name_b = dlt_dissectors[ll_a_value]
        local subtree_b = tree:add(diff_protocol, buffer(b_index), "PCAP B")
        if dissector_name_b then
            Dissector.get(dissector_name_b):call(payload_b, pinfo, tree)
        end

    elseif match == 1 then -- Removed
        local ll_a_value = buffer(1,4):le_uint()
        subtree:add_le(ll_type_a_field, buffer(1,4))
    
        local payload = buffer(5):tvb()
        subtree:add(pcap_a_len_field, payload:len())

        local subtree_a = tree:add(diff_protocol, buffer(5), "PCAP A")        
    
        local dissector_name = dlt_dissectors[ll_a_value]
        if dissector_name then
            Dissector.get(dissector_name):call(payload, pinfo, tree)
        end
    else -- Added
        local ll_b_value = buffer(1,4):le_uint()
        subtree:add_le(ll_type_b_field, buffer(1,4))
    
        local payload = buffer(5):tvb()
        subtree:add(pcap_b_len_field, payload:len())
    
        local subtree_b = tree:add(diff_protocol, buffer(5), "PCAP B")

        local dissector_name = dlt_dissectors[ll_b_value]
        if dissector_name then
            Dissector.get(dissector_name):call(payload, pinfo, tree)
        end
    end  

end

